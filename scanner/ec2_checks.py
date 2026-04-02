from botocore.exceptions import ClientError


def run_checks(session):
	ec2 = session.client("ec2")
	results = []

	def add_result(rule_id, title, status, severity, resource, detail):
		results.append(
			{
				"id": rule_id,
				"title": title,
				"status": status,
				"severity": severity,
				"service": "EC2",
				"resource": resource,
				"detail": detail,
			}
		)

	def _perm_allows_port_from_cidr(perm, port, cidr_value, field_name):
		ip_protocol = perm.get("IpProtocol")
		from_port = perm.get("FromPort")
		to_port = perm.get("ToPort")

		# Protocol -1 means all protocols/ports.
		port_match = (
			ip_protocol == "-1"
			or (from_port is not None and to_port is not None and from_port <= port <= to_port)
		)
		if not port_match:
			return False

		for cidr in perm.get(field_name, []):
			if cidr.get("CidrIp") == cidr_value or cidr.get("CidrIpv6") == cidr_value:
				return True
		return False

	# Fetch security groups once for checks 1 and 2.
	sg_fetch_failed = False
	try:
		sg_response = ec2.describe_security_groups()
		security_groups = sg_response.get("SecurityGroups", [])
	except ClientError as exc:
		sg_fetch_failed = True
		add_result(
			"4.1",
			"Ensure no security groups allow SSH from the internet",
			"FAIL",
			"CRITICAL",
			"security-groups",
			f"Unable to describe security groups: {exc}",
		)
		add_result(
			"4.2",
			"Ensure no security groups allow RDP from the internet",
			"FAIL",
			"CRITICAL",
			"security-groups",
			f"Unable to describe security groups: {exc}",
		)
		security_groups = []

	# 1) SSH exposed to 0.0.0.0/0 or ::/0 on port 22.
	if not sg_fetch_failed:
		ssh_exposed = []
		for sg in security_groups:
			group_id = sg.get("GroupId", "unknown-sg")
			group_name = sg.get("GroupName", "")
			for perm in sg.get("IpPermissions", []):
				ipv4_open = _perm_allows_port_from_cidr(perm, 22, "0.0.0.0/0", "IpRanges")
				ipv6_open = _perm_allows_port_from_cidr(perm, 22, "::/0", "Ipv6Ranges")
				if ipv4_open or ipv6_open:
					ssh_exposed.append(f"{group_id}({group_name})")
					break

		compliant = len(ssh_exposed) == 0
		add_result(
			"4.1",
			"Ensure no security groups allow SSH from the internet",
			"PASS" if compliant else "FAIL",
			"CRITICAL",
			"security-groups",
			"No security groups expose SSH (22) to 0.0.0.0/0 or ::/0."
			if compliant
			else "Security groups exposing SSH: " + ", ".join(ssh_exposed),
		)

	# 2) RDP exposed to 0.0.0.0/0 on port 3389.
	if not sg_fetch_failed:
		rdp_exposed = []
		for sg in security_groups:
			group_id = sg.get("GroupId", "unknown-sg")
			group_name = sg.get("GroupName", "")
			for perm in sg.get("IpPermissions", []):
				ipv4_open = _perm_allows_port_from_cidr(perm, 3389, "0.0.0.0/0", "IpRanges")
				if ipv4_open:
					rdp_exposed.append(f"{group_id}({group_name})")
					break

		compliant = len(rdp_exposed) == 0
		add_result(
			"4.2",
			"Ensure no security groups allow RDP from the internet",
			"PASS" if compliant else "FAIL",
			"CRITICAL",
			"security-groups",
			"No security groups expose RDP (3389) to 0.0.0.0/0."
			if compliant
			else "Security groups exposing RDP: " + ", ".join(rdp_exposed),
		)

	# 3) EBS volumes not encrypted.
	try:
		volumes = ec2.describe_volumes().get("Volumes", [])
		unencrypted_vols = [
			vol.get("VolumeId", "unknown-volume")
			for vol in volumes
			if not vol.get("Encrypted", False)
		]
		compliant = len(unencrypted_vols) == 0
		add_result(
			"2.2.1",
			"Ensure EBS volumes are encrypted",
			"PASS" if compliant else "FAIL",
			"HIGH",
			"ebs-volumes",
			"All EBS volumes are encrypted."
			if compliant
			else "Unencrypted EBS volumes: " + ", ".join(unencrypted_vols),
		)
	except ClientError as exc:
		add_result(
			"2.2.1",
			"Ensure EBS volumes are encrypted",
			"FAIL",
			"HIGH",
			"ebs-volumes",
			f"Unable to describe EBS volumes: {exc}",
		)

	# 4) EC2 instances running in the default VPC.
	try:
		# Build a lookup of VpcId -> IsDefault.
		vpcs = ec2.describe_vpcs().get("Vpcs", [])
		default_map = {vpc.get("VpcId"): bool(vpc.get("IsDefault", False)) for vpc in vpcs}

		instances_in_default_vpc = []
		paginator = ec2.get_paginator("describe_instances")
		for page in paginator.paginate():
			for reservation in page.get("Reservations", []):
				for instance in reservation.get("Instances", []):
					instance_id = instance.get("InstanceId", "unknown-instance")
					vpc_id = instance.get("VpcId")
					if vpc_id and default_map.get(vpc_id, False):
						instances_in_default_vpc.append(f"{instance_id}({vpc_id})")

		compliant = len(instances_in_default_vpc) == 0
		add_result(
			"4.3",
			"Ensure EC2 instances are not running in the default VPC",
			"PASS" if compliant else "FAIL",
			"MEDIUM",
			"ec2-instances",
			"No EC2 instances are running in default VPCs."
			if compliant
			else "Instances in default VPC: " + ", ".join(instances_in_default_vpc),
		)
	except ClientError as exc:
		add_result(
			"4.3",
			"Ensure EC2 instances are not running in the default VPC",
			"FAIL",
			"MEDIUM",
			"ec2-instances",
			f"Unable to describe EC2 instances or VPCs: {exc}",
		)

	return results
