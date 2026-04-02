from datetime import datetime, timedelta, timezone


def run_checks(session):
	iam = session.client("iam")
	results = []

	def add_result(rule_id, title, status, severity, service, resource, detail):
		results.append(
			{
				"id": rule_id,
				"title": title,
				"status": status,
				"severity": severity,
				"service": service,
				"resource": resource,
				"detail": detail,
			}
		)

	# 1) Root account MFA enabled
	try:
		summary = iam.get_account_summary().get("SummaryMap", {})
		root_mfa_enabled = int(summary.get("AccountMFAEnabled", 0)) == 1
		add_result(
			"1.5",
			"Ensure MFA is enabled for the root account",
			"PASS" if root_mfa_enabled else "FAIL",
			"CRITICAL",
			"IAM",
			"root-account",
			"Root account MFA is enabled."
			if root_mfa_enabled
			else "Root account MFA is not enabled.",
		)
	except Exception as exc:
		add_result(
			"1.5",
			"Ensure MFA is enabled for the root account",
			"FAIL",
			"CRITICAL",
			"IAM",
			"root-account",
			f"Unable to evaluate root MFA status: {exc}",
		)

	# 2) Each IAM user has MFA enabled
	try:
		users = []
		marker = None
		while True:
			kwargs = {}
			if marker:
				kwargs["Marker"] = marker
			page = iam.list_users(**kwargs)
			users.extend(page.get("Users", []))
			if not page.get("IsTruncated"):
				break
			marker = page.get("Marker")

		mfa_users = set()
		marker = None
		while True:
			kwargs = {"AssignmentStatus": "Assigned"}
			if marker:
				kwargs["Marker"] = marker
			page = iam.list_virtual_mfa_devices(**kwargs)
			for device in page.get("VirtualMFADevices", []):
				user = device.get("User")
				if user and user.get("UserName"):
					mfa_users.add(user["UserName"])
			if not page.get("IsTruncated"):
				break
			marker = page.get("Marker")

		users_without_mfa = [
			user.get("UserName")
			for user in users
			if user.get("UserName") and user.get("UserName") not in mfa_users
		]

		all_have_mfa = len(users_without_mfa) == 0
		detail = (
			"All IAM users have virtual MFA enabled."
			if all_have_mfa
			else "IAM users without MFA: " + ", ".join(users_without_mfa)
		)

		add_result(
			"1.10",
			"Ensure MFA is enabled for all IAM users",
			"PASS" if all_have_mfa else "FAIL",
			"HIGH",
			"IAM",
			"all-iam-users",
			detail,
		)
	except Exception as exc:
		add_result(
			"1.10",
			"Ensure MFA is enabled for all IAM users",
			"FAIL",
			"HIGH",
			"IAM",
			"all-iam-users",
			f"Unable to evaluate IAM user MFA coverage: {exc}",
		)

	# 3) Password policy minimum length >= 14
	try:
		policy = iam.get_account_password_policy().get("PasswordPolicy", {})
		min_len = int(policy.get("MinimumPasswordLength", 0))
		compliant = min_len >= 14
		add_result(
			"1.8",
			"Ensure IAM password policy minimum length is at least 14",
			"PASS" if compliant else "FAIL",
			"HIGH",
			"IAM",
			"account-password-policy",
			f"MinimumPasswordLength is {min_len}."
			if compliant
			else f"MinimumPasswordLength is {min_len}, expected >= 14.",
		)
	except Exception as exc:
		add_result(
			"1.8",
			"Ensure IAM password policy minimum length is at least 14",
			"FAIL",
			"HIGH",
			"IAM",
			"account-password-policy",
			f"Password policy missing or unreadable: {exc}",
		)

	# 4) No IAM access keys unused for more than 90 days
	try:
		cutoff = datetime.now(timezone.utc) - timedelta(days=90)
		stale_keys = []

		marker = None
		users = []
		while True:
			kwargs = {}
			if marker:
				kwargs["Marker"] = marker
			page = iam.list_users(**kwargs)
			users.extend(page.get("Users", []))
			if not page.get("IsTruncated"):
				break
			marker = page.get("Marker")

		for user in users:
			username = user.get("UserName")
			if not username:
				continue

			key_marker = None
			while True:
				kwargs = {"UserName": username}
				if key_marker:
					kwargs["Marker"] = key_marker
				key_page = iam.list_access_keys(**kwargs)

				for key_meta in key_page.get("AccessKeyMetadata", []):
					if key_meta.get("Status") != "Active":
						continue

					access_key_id = key_meta.get("AccessKeyId")
					if not access_key_id:
						continue

					last_used_resp = iam.get_access_key_last_used(
						AccessKeyId=access_key_id
					)
					last_used = (
						last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
					)
					create_date = key_meta.get("CreateDate")

					# Treat never-used keys older than 90 days as stale.
					if last_used is None:
						if create_date and create_date < cutoff:
							stale_keys.append(f"{username}:{access_key_id}(never used)")
					elif last_used < cutoff:
						stale_keys.append(f"{username}:{access_key_id}")

				if not key_page.get("IsTruncated"):
					break
				key_marker = key_page.get("Marker")

		compliant = len(stale_keys) == 0
		add_result(
			"1.14",
			"Ensure no IAM access keys are unused for more than 90 days",
			"PASS" if compliant else "FAIL",
			"MEDIUM",
			"IAM",
			"iam-access-keys",
			"No stale active access keys found."
			if compliant
			else "Stale active access keys: " + ", ".join(stale_keys),
		)
	except Exception as exc:
		add_result(
			"1.14",
			"Ensure no IAM access keys are unused for more than 90 days",
			"FAIL",
			"MEDIUM",
			"IAM",
			"iam-access-keys",
			f"Unable to evaluate access key usage age: {exc}",
		)

	# 5) Root account has no active access keys
	try:
		summary = iam.get_account_summary().get("SummaryMap", {})
		root_keys = int(summary.get("AccountAccessKeysPresent", 0))
		compliant = root_keys == 0
		add_result(
			"1.12",
			"Ensure no active access keys exist for the root account",
			"PASS" if compliant else "FAIL",
			"CRITICAL",
			"IAM",
			"root-account",
			"Root account has no active access keys."
			if compliant
			else f"Root account has {root_keys} active access key(s).",
		)
	except Exception as exc:
		add_result(
			"1.12",
			"Ensure no active access keys exist for the root account",
			"FAIL",
			"CRITICAL",
			"IAM",
			"root-account",
			f"Unable to evaluate root account access keys: {exc}",
		)

	return results
