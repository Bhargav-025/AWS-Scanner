def run_all_checks(session):
	results = []

	modules = [
		("iam_checks", "IAM"),
		("s3_checks", "S3"),
		("ec2_checks", "EC2"),
		("cloudtrail_checks", "CloudTrail"),
	]

	for module_name, service_name in modules:
		try:
			module = __import__(f"scanner.{module_name}", fromlist=["run_checks"])
			module_results = module.run_checks(session)
			if isinstance(module_results, list):
				results.extend(module_results)
		except Exception as exc:
			results.append(
				{
					"id": f"{module_name}.scan_error",
					"title": f"{service_name} scan failed",
					"status": "FAIL",
					"severity": "HIGH",
					"service": service_name,
					"resource": service_name.lower(),
					"detail": f"Unable to run {module_name}: {exc}",
				}
			)

	return results


def calculate_summary(results):
	summary = {
		"total": len(results),
		"pass_count": 0,
		"fail_count": 0,
		"critical_count": 0,
		"high_count": 0,
		"medium_count": 0,
		"low_count": 0,
		"risk_score": 100,
	}

	severity_penalties = {
		"CRITICAL": 15,
		"HIGH": 8,
		"MEDIUM": 3,
		"LOW": 1,
	}

	risk_score = 100

	for result in results:
		status = str(result.get("status", "")).upper()
		severity = str(result.get("severity", "")).upper()

		if status == "PASS":
			summary["pass_count"] += 1
			continue

		if status == "FAIL":
			summary["fail_count"] += 1
			if severity == "CRITICAL":
				summary["critical_count"] += 1
			elif severity == "HIGH":
				summary["high_count"] += 1
			elif severity == "MEDIUM":
				summary["medium_count"] += 1
			elif severity == "LOW":
				summary["low_count"] += 1

			risk_score -= severity_penalties.get(severity, 0)

	summary["risk_score"] = max(0, risk_score)
	return summary
