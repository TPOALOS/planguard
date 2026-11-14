# planguard

**Catch the Terraform change you would regret, before `terraform apply`.** A plan that looks like "5 changes" can hide a database replace, a
security group open to the whole internet on SSH, a bucket flipped to public, or encryption quietly switched off. planguard reads the JSON
form of a plan (`terraform show -json plan.out`), lists the risky changes with a fix for each, and exits non-zero so CI can stop the apply.
It never runs terraform and never executes anything from the plan.

```
$ terraform show -json plan.out > plan.json
$ planguard plan.json
planguard: 5 resource change(s): add 2, change 1, delete 1, replace 1
CRITICAL PG-REPLACE   aws_db_instance.main
         aws_db_instance will be REPLACED (destroyed then recreated); data and identity attached to the old object are lost
         fix: Find the attribute forcing replacement (see `replace_paths`/`terraform show`), revert it, or use a snapshot, `terraform state mv` or `moved` block; if intended, re-run with --allow-destroy aws_db_instance
CRITICAL PG-DESTROY   aws_kms_key.old
         aws_kms_key will be DESTROYED
         fix: Confirm a backup/snapshot exists, remove the resource from the plan or use `terraform state rm` if it must survive; if intended, re-run with --allow-destroy aws_kms_key
CRITICAL PG-S3-PUBLIC aws_s3_bucket_acl.logs
         bucket ACL set to public-read
         fix: Use acl = "private", keep a public access block, and serve content through CloudFront with OAC
HIGH     PG-DELPROT   aws_db_instance.main
         deletion_protection switched off (was true)
         fix: Leave deletion_protection = true and add lifecycle { prevent_destroy = true }; disable only in a reviewed, separate change
HIGH     PG-ENCRYPTION aws_db_instance.main
         aws_db_instance: storage_encrypted is false (was true)
         fix: Set storage_encrypted = true (and a customer-managed kms_key_id if policy requires); changing it on existing storage often forces replacement
HIGH     PG-SG-OPEN   aws_security_group.web
         aws_security_group opened to 0.0.0.0/0 on 22/SSH
         fix: Restrict the source to a known CIDR, security group or VPN range; use SSM Session Manager/bastion instead of public admin ports
MEDIUM   PG-PUBLIC-IP aws_db_instance.main
         publicly_accessible = true: resource gets a public address
         fix: Place it in a private subnet behind a load balancer/NAT unless public exposure is required
MEDIUM   PG-PUBLIC-IP aws_instance.app
         associate_public_ip_address = true: resource gets a public address
         fix: Place it in a private subnet behind a load balancer/NAT unless public exposure is required
```

Values the plan marks sensitive (and attributes named like `password`, `token`, `secret`) are redacted before any check, so they cannot appear in the output.

## Usage

```bash
terraform show -json plan.out | planguard            # stdin
planguard plan.json                                  # file
planguard plan.json --fail-on high                   # only HIGH and CRITICAL fail the build
planguard plan.json --allow-destroy aws_s3_bucket    # this destroy is intended (glob ok, repeatable)
planguard plan.json --json                           # machine-readable
```

Start of the `--json` output (same plan, `--fail-on critical --allow-destroy aws_kms_key`):

```json
{
  "tool": "planguard",
  "version": "1.0.0",
  "summary": {
    "add": 2,
    "change": 1,
    "delete": 1,
    "replace": 1,
    "read": 0,
    "no-op": 0,
    "total": 5
  },
  "fail_on": "critical",
  "findings": [
    {
      "rule": "PG-REPLACE",
  ...
```

## What it flags

| Rule | Severity | Meaning |
|---|---|---|
| `PG-DESTROY` / `PG-REPLACE` | HIGH to CRITICAL | delete, or delete+create, of databases, buckets, volumes, KMS keys, DNS zones, IAM, VPC and similar (AWS, GCP, Azure lists in the source); also `skip_final_snapshot` and `force_destroy` on delete |
| `PG-SG-OPEN` | HIGH / CRITICAL | newly added ingress from `0.0.0.0/0` or `::/0` to 22, 3389, 3306, 5432, 6379, 27017 and other sensitive ports (CRITICAL when all ports); `aws_security_group`, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, `google_compute_firewall`, `azurerm_network_security_*` |
| `PG-S3-PUBLIC` | HIGH / CRITICAL | public ACL, public-access-block settings turned false or removed, bucket policy with `Principal "*"` and no Condition, GCS `allUsers` |
| `PG-ENCRYPTION` | MEDIUM / HIGH | `encrypted`, `storage_encrypted`, ... false (turned off, or created off); key rotation off; bucket encryption config removed |
| `PG-DELPROT` | MEDIUM / HIGH | `deletion_protection`-style flags true to false; `force_destroy` turned on |
| `PG-PUBLIC-IP` | LOW / MEDIUM | `associate_public_ip_address`, `map_public_ip_on_launch`, `publicly_accessible` turned on; new EIP / public IP; GCP `access_config` |

Only exposures that are **new** in the plan are reported (a rule that already existed in `before` is not repeated). The summary line counts
add / change / delete / replace.

Exit codes: `0` nothing at or above `--fail-on` (default `low`, i.e. any finding fails), `1` findings, `2` usage or input error
(bad JSON, not a plan, not a regular file, over 64 MiB).

## Limits

- It reads the plan JSON only. It does not know what `terraform apply` will really do beyond what the plan states: values "known after apply"
  are absent, so a risky value that is computed later cannot be judged.
- Resource coverage is a fixed list of common AWS, GCP and Azure types and attribute names; other providers and custom modules' naming are not covered.
  Security-group checks cover the resource types named above, not every firewall construct (for example AWS network ACLs, Azure NSG rules via other resources).
- A value marked sensitive is redacted, which also means a check cannot judge it (for example a sensitive `acl`).
- Port checks look at the CIDR/ports in the plan; they do not follow security-group references, peering, route tables or load balancers, so "open to the internet" is not proven reachable.
- Policy documents (`aws_iam_policy`, bucket policies beyond the public-principal check) are not analysed; use a policy linter for those.
- Resource `prevent_destroy` lifecycle settings are not in the plan JSON, so they cannot be checked.
- It is a review aid, not a substitute for policy-as-code engines or human review.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
