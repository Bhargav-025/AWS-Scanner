from botocore.exceptions import ClientError


def run_checks(session):
	s3 = session.client("s3")
	results = []

	def add_result(rule_id, title, status, severity, bucket_name, detail):
		results.append(
			{
				"id": rule_id,
				"title": title,
				"status": status,
				"severity": severity,
				"service": "S3",
				"resource": bucket_name,
				"detail": detail,
			}
		)

	try:
		buckets = s3.list_buckets().get("Buckets", [])
	except ClientError as exc:
		add_result(
			"2.1.0",
			"Enumerate S3 buckets",
			"FAIL",
			"HIGH",
			"account",
			f"Unable to list S3 buckets: {exc}",
		)
		return results

	for bucket in buckets:
		bucket_name = bucket.get("Name", "unknown-bucket")

		# 1) Block Public Access fully enabled
		try:
			pab = s3.get_public_access_block(Bucket=bucket_name).get(
				"PublicAccessBlockConfiguration", {}
			)
			all_enabled = all(
				[
					pab.get("BlockPublicAcls") is True,
					pab.get("IgnorePublicAcls") is True,
					pab.get("BlockPublicPolicy") is True,
					pab.get("RestrictPublicBuckets") is True,
				]
			)
			add_result(
				"2.1.2",
				"Ensure S3 Block Public Access is fully enabled",
				"PASS" if all_enabled else "FAIL",
				"CRITICAL",
				bucket_name,
				"All four Block Public Access settings are enabled."
				if all_enabled
				else "One or more Block Public Access settings are disabled.",
			)
		except ClientError as exc:
			add_result(
				"2.1.2",
				"Ensure S3 Block Public Access is fully enabled",
				"FAIL",
				"CRITICAL",
				bucket_name,
				f"Unable to read Public Access Block configuration: {exc}",
			)

		# 2) Server-side encryption configured
		try:
			enc = s3.get_bucket_encryption(Bucket=bucket_name)
			rules = (
				enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
			)
			configured = len(rules) > 0
			add_result(
				"2.1.4",
				"Ensure server-side encryption is configured for S3 buckets",
				"PASS" if configured else "FAIL",
				"HIGH",
				bucket_name,
				"Server-side encryption configuration is present."
				if configured
				else "Server-side encryption configuration is missing.",
			)
		except ClientError as exc:
			code = exc.response.get("Error", {}).get("Code", "")
			if code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket"):
				add_result(
					"2.1.4",
					"Ensure server-side encryption is configured for S3 buckets",
					"FAIL",
					"HIGH",
					bucket_name,
					"Server-side encryption configuration is missing.",
				)
			else:
				add_result(
					"2.1.4",
					"Ensure server-side encryption is configured for S3 buckets",
					"FAIL",
					"HIGH",
					bucket_name,
					f"Unable to read bucket encryption configuration: {exc}",
				)

		# 3) Versioning enabled
		try:
			versioning = s3.get_bucket_versioning(Bucket=bucket_name)
			enabled = versioning.get("Status") == "Enabled"
			add_result(
				"2.1.3",
				"Ensure S3 bucket versioning is enabled",
				"PASS" if enabled else "FAIL",
				"MEDIUM",
				bucket_name,
				"Versioning is enabled."
				if enabled
				else "Versioning is not enabled.",
			)
		except ClientError as exc:
			add_result(
				"2.1.3",
				"Ensure S3 bucket versioning is enabled",
				"FAIL",
				"MEDIUM",
				bucket_name,
				f"Unable to read versioning status: {exc}",
			)

		# 4) Access logging enabled
		try:
			logging_status = s3.get_bucket_logging(Bucket=bucket_name)
			enabled = bool(logging_status.get("LoggingEnabled"))
			add_result(
				"2.2.1",
				"Ensure S3 access logging is enabled",
				"PASS" if enabled else "FAIL",
				"MEDIUM",
				bucket_name,
				"Access logging is enabled."
				if enabled
				else "Access logging is not enabled.",
			)
		except ClientError as exc:
			add_result(
				"2.2.1",
				"Ensure S3 access logging is enabled",
				"FAIL",
				"MEDIUM",
				bucket_name,
				f"Unable to read bucket logging configuration: {exc}",
			)

	return results
