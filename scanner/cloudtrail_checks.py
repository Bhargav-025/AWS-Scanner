from botocore.exceptions import ClientError


def run_checks(session):
	cloudtrail = session.client("cloudtrail")
	s3 = session.client("s3")
	results = []

	def add_result(rule_id, title, status, severity, resource, detail):
		results.append(
			{
				"id": rule_id,
				"title": title,
				"status": status,
				"severity": severity,
				"service": "CloudTrail",
				"resource": resource,
				"detail": detail,
			}
		)

	try:
		trails = cloudtrail.list_trails(includeShadowTrails=False).get("Trails", [])
	except ClientError as exc:
		add_result(
			"3.1",
			"Ensure at least one CloudTrail trail exists",
			"FAIL",
			"CRITICAL",
			"account",
			f"Unable to list CloudTrail trails: {exc}",
		)
		return results

	if not trails:
		add_result(
			"3.1",
			"Ensure at least one CloudTrail trail exists",
			"FAIL",
			"CRITICAL",
			"account",
			"No CloudTrail trails exist, so all CloudTrail checks fail.",
		)
		return results

	for trail in trails:
		trail_name = trail.get("Name") or trail.get("TrailARN") or "unknown-trail"

		# 1) At least one CloudTrail trail exists
		add_result(
			"3.1",
			"Ensure at least one CloudTrail trail exists",
			"PASS",
			"CRITICAL",
			trail_name,
			"CloudTrail trail exists.",
		)

		# 2) CloudTrail logging is active
		try:
			status = cloudtrail.get_trail_status(Name=trail_name)
			logging_active = bool(status.get("IsLogging", False))
			add_result(
				"3.2",
				"Ensure CloudTrail logging is enabled",
				"PASS" if logging_active else "FAIL",
				"CRITICAL",
				trail_name,
				"CloudTrail logging is active."
				if logging_active
				else "CloudTrail logging is not active.",
			)
		except ClientError as exc:
			add_result(
				"3.2",
				"Ensure CloudTrail logging is enabled",
				"FAIL",
				"CRITICAL",
				trail_name,
				f"Unable to read trail status: {exc}",
			)

		# 3) Log file validation enabled
		try:
			trail_info = cloudtrail.get_trail(Name=trail_name).get("Trail", {})
			validation_enabled = bool(trail_info.get("LogFileValidationEnabled", False))
			add_result(
				"3.3",
				"Ensure CloudTrail log file validation is enabled",
				"PASS" if validation_enabled else "FAIL",
				"MEDIUM",
				trail_name,
				"Log file validation is enabled."
				if validation_enabled
				else "Log file validation is not enabled.",
			)
		except ClientError as exc:
			add_result(
				"3.3",
				"Ensure CloudTrail log file validation is enabled",
				"FAIL",
				"MEDIUM",
				trail_name,
				f"Unable to read trail configuration: {exc}",
			)

		# 4) CloudTrail is multi-region
		try:
			trail_info = cloudtrail.get_trail(Name=trail_name).get("Trail", {})
			multi_region = bool(trail_info.get("IsMultiRegionTrail", False))
			add_result(
				"3.4",
				"Ensure CloudTrail is multi-region",
				"PASS" if multi_region else "FAIL",
				"HIGH",
				trail_name,
				"CloudTrail is multi-region."
				if multi_region
				else "CloudTrail is not multi-region.",
			)
		except ClientError as exc:
			add_result(
				"3.4",
				"Ensure CloudTrail is multi-region",
				"FAIL",
				"HIGH",
				trail_name,
				f"Unable to read trail configuration: {exc}",
			)

		# 5) CloudTrail S3 bucket has access logging enabled
		try:
			trail_info = cloudtrail.get_trail(Name=trail_name).get("Trail", {})
			bucket_name = trail_info.get("S3BucketName")
			if not bucket_name:
				add_result(
					"3.5",
					"Ensure CloudTrail S3 bucket access logging is enabled",
					"FAIL",
					"MEDIUM",
					trail_name,
					"CloudTrail trail does not have an S3 bucket configured.",
				)
			else:
				try:
					logging_status = s3.get_bucket_logging(Bucket=bucket_name)
					enabled = bool(logging_status.get("LoggingEnabled"))
					add_result(
						"3.5",
						"Ensure CloudTrail S3 bucket access logging is enabled",
						"PASS" if enabled else "FAIL",
						"MEDIUM",
						bucket_name,
						"S3 bucket access logging is enabled."
						if enabled
						else "S3 bucket access logging is not enabled.",
					)
				except ClientError as exc:
					add_result(
						"3.5",
						"Ensure CloudTrail S3 bucket access logging is enabled",
						"FAIL",
						"MEDIUM",
						bucket_name,
						f"Unable to read S3 bucket logging configuration: {exc}",
					)
		except ClientError as exc:
			add_result(
				"3.5",
				"Ensure CloudTrail S3 bucket access logging is enabled",
				"FAIL",
				"MEDIUM",
				trail_name,
				f"Unable to read trail configuration: {exc}",
			)

	return results
