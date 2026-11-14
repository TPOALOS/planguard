#!/usr/bin/env python3
"""planguard: report risky changes in a Terraform plan (JSON) before apply.

Reads the output of `terraform show -json plan.out` (a file or stdin) and
reports destroys/replacements of critical resources, world-open sensitive
ports, public buckets, encryption switched off, deletion protection removed,
and newly public IPs. It never runs terraform and never executes anything
from the plan. Values marked sensitive in the plan are redacted.

Exit codes: 0 no findings at or above --fail-on, 1 findings, 2 usage/input error.
"""
import argparse
import fnmatch
import json
import os
import re
import stat
import sys

__version__ = "1.0.0"

MAX_BYTES = 64 * 1024 * 1024
REDACTED = "[REDACTED]"
SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_NAMES = {v: k.upper() for k, v in SEV_ORDER.items()}

# Resource types whose loss is hard or impossible to undo.
CRITICAL_DATA = [
    r"aws_db_instance", r"aws_rds_cluster", r"aws_rds_cluster_instance", r"aws_s3_bucket",
    r"aws_ebs_volume", r"aws_efs_file_system", r"aws_dynamodb_table", r"aws_kms_key",
    r"aws_kms_alias", r"aws_elasticache_(cluster|replication_group)", r"aws_redshift_cluster",
    r"aws_docdb_cluster", r"aws_neptune_cluster", r"aws_secretsmanager_secret",
    r"aws_opensearch_domain", r"aws_elasticsearch_domain", r"aws_backup_vault",
    r"google_sql_database_instance", r"google_storage_bucket", r"google_kms_crypto_key",
    r"google_kms_key_ring", r"google_bigtable_instance", r"google_spanner_instance",
    r"google_compute_disk", r"azurerm_(mssql|mysql|postgresql|mariadb)_.*(server|database)",
    r"azurerm_storage_account", r"azurerm_key_vault", r"azurerm_cosmosdb_account",
    r"azurerm_managed_disk",
]
CRITICAL_OTHER = [
    r"aws_route53_zone", r"aws_route53_record", r"aws_iam_.*", r"aws_vpc", r"aws_subnet",
    r"aws_internet_gateway", r"aws_nat_gateway", r"aws_vpn_.*", r"aws_ec2_transit_gateway",
    r"aws_acm_certificate", r"aws_cloudfront_distribution", r"aws_organizations_.*",
    r"google_dns_managed_zone", r"google_compute_network", r"google_compute_subnetwork",
    r"google_project", r"google_project_iam_.*", r"google_service_account",
    r"azurerm_dns_zone", r"azurerm_virtual_network", r"azurerm_role_assignment",
    r"azurerm_resource_group", r"cloudflare_zone",
]
_DATA_RE = re.compile(r"^(?:%s)$" % "|".join(CRITICAL_DATA))
_OTHER_RE = re.compile(r"^(?:%s)$" % "|".join(CRITICAL_OTHER))

SENSITIVE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker API", 2379: "etcd",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
    6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}
OPEN_V4 = {"0.0.0.0/0"}
OPEN_V6 = {"::/0", "0000:0000:0000:0000:0000:0000:0000:0000/0"}
OPEN_WORDS = {"*", "any", "internet", "0.0.0.0", "0.0.0.0/0", "::/0", "::"}

SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|private_key|api_key|access_key|credential|connection_string)", re.I)

ENC_ATTRS = ("encrypted", "storage_encrypted", "encryption_enabled", "enable_encryption",
             "server_side_encryption_enabled", "kms_encrypted")
DELPROT_ATTRS = ("deletion_protection", "deletion_protection_enabled", "enable_deletion_protection",
                 "delete_protection", "termination_protection", "prevent_destroy",
                 "enable_termination_protection")
DELPROT_INVERSE = ("disable_api_termination",)
PUBLIC_IP_ATTRS = ("associate_public_ip_address", "map_public_ip_on_launch", "publicly_accessible")
CIDR_BLOCK_ACLS = ("public-read", "public-read-write", "authenticated-read")

_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")


def clean(s, limit=200):
    """Strip control and bidi characters so hostile names cannot spoof the output."""
    s = _CTRL_RE.sub("?", str(s))
    return s if len(s) <= limit else s[:limit - 3] + "..."


class Finding(object):
    def __init__(self, rule, severity, address, message, fix, evidence=None):
        self.rule = rule
        self.severity = severity
        self.address = clean(address)
        self.message = clean(message, 400)
        self.fix = clean(fix, 400)
        self.evidence = clean(evidence, 300) if evidence else None

    def as_dict(self):
        d = {"rule": self.rule, "severity": SEV_NAMES[self.severity], "address": self.address,
             "message": self.message, "fix": self.fix}
        if self.evidence:
            d["evidence"] = self.evidence
        return d


# --------------------------------------------------------------- plan loading

class PlanError(Exception):
    pass


def read_source(path, stdin=None):
    """Read bytes from a file (regular files only, capped) or stdin when path is '-'."""
    if path == "-":
        stream = stdin if stdin is not None else sys.stdin.buffer
        data = stream.read(MAX_BYTES + 1)
    else:
        try:
            st = os.stat(path)
        except OSError as e:
            raise PlanError("cannot read %s: %s" % (clean(path), e.strerror or e))
        if not stat.S_ISREG(st.st_mode):
            raise PlanError("%s is not a regular file" % clean(path))
        try:
            with open(path, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise PlanError("cannot read %s: %s" % (clean(path), e.strerror or e))
    if len(data) > MAX_BYTES:
        raise PlanError("input larger than %d MiB, refusing" % (MAX_BYTES // 1024 // 1024))
    return data


def parse_plan(data):
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise PlanError("input is not valid UTF-8 text")
    try:
        plan = json.loads(text)
    except (ValueError, RecursionError):
        raise PlanError("input is not valid JSON (expected `terraform show -json` output)")
    if not isinstance(plan, dict):
        raise PlanError("plan JSON must be an object")
    rc = plan.get("resource_changes", [])
    if rc is None:
        rc = []
    if not isinstance(rc, list):
        raise PlanError("resource_changes must be a list")
    if "resource_changes" not in plan and "planned_values" not in plan and "format_version" not in plan:
        raise PlanError("does not look like a Terraform plan (no resource_changes/format_version)")
    return plan


def scrub(value, mask, depth=0):
    """Replace values the plan marks sensitive (and secret-looking keys) with REDACTED."""
    if mask is True:
        return REDACTED
    if depth > 60:
        return REDACTED
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            m = mask.get(k) if isinstance(mask, dict) else None
            if isinstance(k, str) and SECRET_KEY_RE.search(k) and not isinstance(v, (dict, list)) \
                    and not isinstance(v, bool) and v is not None:
                out[k] = REDACTED
            else:
                out[k] = scrub(v, m, depth + 1)
        return out
    if isinstance(value, list):
        out = []
        for i, v in enumerate(value):
            m = mask[i] if isinstance(mask, list) and i < len(mask) else None
            out.append(scrub(v, m, depth + 1))
        return out
    return value


# --------------------------------------------------------------- helpers

def action_kind(actions):
    if not isinstance(actions, list):
        return "unknown"
    s = set(a for a in actions if isinstance(a, str))
    if "delete" in s and "create" in s:
        return "replace"
    if "delete" in s:
        return "delete"
    if "create" in s:
        return "create"
    if "update" in s:
        return "update"
    if "read" in s:
        return "read"
    if s == {"no-op"} or not s:
        return "no-op"
    return "unknown"


def is_critical(rtype):
    if _DATA_RE.match(rtype):
        return 4
    if _OTHER_RE.match(rtype):
        return 3
    return 0


def as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def parse_port(p):
    try:
        return int(str(p).strip())
    except (ValueError, TypeError):
        return None


def exposed_ports(lo, hi, proto):
    """Return a description of sensitive ports reachable in the range, or 'all ports'."""
    proto = str(proto).lower() if proto is not None else ""
    if proto in ("-1", "all", "*", "any"):
        return ["all ports"]
    lo = parse_port(lo)
    hi = parse_port(hi)
    if lo is None and hi is None:
        return ["all ports"] if proto in ("", "tcp", "udp") and lo is None and hi is None else []
    if lo is None:
        lo = hi
    if hi is None:
        hi = lo
    if lo > hi:
        lo, hi = hi, lo
    if lo <= 0 and hi >= 65535:
        return ["all ports"]
    if proto == "icmp":
        return []
    hits = ["%d/%s" % (p, SENSITIVE_PORTS[p]) for p in sorted(SENSITIVE_PORTS) if lo <= p <= hi]
    if not hits and hi - lo >= 1000:
        hits = ["wide range %d-%d" % (lo, hi)]
    return hits


def _is_open(cidr):
    return isinstance(cidr, str) and cidr.strip().lower() in OPEN_V4 | OPEN_V6


# --------------------------------------------------------------- exposure extractors

def exposures(rtype, attrs):
    """Return a set of (source, port description) tuples that expose sensitive ports to the world."""
    out = set()
    if not isinstance(attrs, dict):
        return out

    def add(sources, lo, hi, proto):
        for s in sources:
            if _is_open(s) or (isinstance(s, str) and s.strip().lower() in OPEN_WORDS):
                for port in exposed_ports(lo, hi, proto):
                    out.add((s.strip(), port))

    if rtype == "aws_security_group":
        for r in as_list(attrs.get("ingress")):
            if isinstance(r, dict):
                add(as_list(r.get("cidr_blocks")) + as_list(r.get("ipv6_cidr_blocks")),
                    r.get("from_port"), r.get("to_port"), r.get("protocol"))
    elif rtype == "aws_security_group_rule":
        if str(attrs.get("type", "")).lower() == "ingress":
            add(as_list(attrs.get("cidr_blocks")) + as_list(attrs.get("ipv6_cidr_blocks")),
                attrs.get("from_port"), attrs.get("to_port"), attrs.get("protocol"))
    elif rtype == "aws_vpc_security_group_ingress_rule":
        add([attrs.get("cidr_ipv4"), attrs.get("cidr_ipv6")],
            attrs.get("from_port"), attrs.get("to_port"), attrs.get("ip_protocol"))
    elif rtype == "google_compute_firewall":
        if str(attrs.get("direction", "INGRESS")).upper() == "INGRESS" and not attrs.get("disabled"):
            for a in as_list(attrs.get("allow")):
                if not isinstance(a, dict):
                    continue
                proto = a.get("protocol")
                ports = as_list(a.get("ports"))
                if not ports:
                    add(as_list(attrs.get("source_ranges")), None, None, proto)
                for p in ports:
                    p = str(p)
                    lo, _, hi = p.partition("-")
                    add(as_list(attrs.get("source_ranges")), lo, hi or lo, proto)
    elif rtype in ("azurerm_network_security_rule", "azurerm_network_security_group"):
        rules = [attrs] if rtype == "azurerm_network_security_rule" else \
            [r for r in as_list(attrs.get("security_rule")) if isinstance(r, dict)]
        for r in rules:
            if str(r.get("direction", "")).lower() != "inbound" or str(r.get("access", "")).lower() != "allow":
                continue
            srcs = as_list(r.get("source_address_prefix")) + as_list(r.get("source_address_prefixes"))
            ports = as_list(r.get("destination_port_range")) + as_list(r.get("destination_port_ranges"))
            proto = r.get("protocol")
            if str(proto).lower() == "*":
                proto = "-1"
            for p in ports:
                p = str(p)
                if p == "*":
                    add(srcs, 0, 65535, proto)
                    continue
                lo, _, hi = p.partition("-")
                add(srcs, lo, hi or lo, proto)
    return out


def policy_public(doc):
    """True if a JSON bucket policy string allows a wildcard principal with no Condition."""
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (ValueError, RecursionError):
            return False
    if not isinstance(doc, dict):
        return False
    for st in as_list(doc.get("Statement")):
        if not isinstance(st, dict) or st.get("Effect") != "Allow" or st.get("Condition"):
            continue
        p = st.get("Principal")
        if p == "*" or (isinstance(p, dict) and "*" in as_list(p.get("AWS"))):
            return True
    return False


# --------------------------------------------------------------- checks

def check_resource(rc, allow_destroy):
    findings = []
    if not isinstance(rc, dict):
        return findings
    address = rc.get("address") or "%s.%s" % (rc.get("type", "?"), rc.get("name", "?"))
    rtype = rc.get("type") if isinstance(rc.get("type"), str) else ""
    change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
    kind = action_kind(change.get("actions"))
    before = scrub(change.get("before"), change.get("before_sensitive"))
    after = scrub(change.get("after"), change.get("after_sensitive"))
    before = before if isinstance(before, dict) else {}
    after = after if isinstance(after, dict) else {}
    if rc.get("mode") == "data":
        return findings

    # destroy / replace of critical types
    if kind in ("delete", "replace"):
        crit = is_critical(rtype)
        allowed = any(fnmatch.fnmatchcase(rtype, pat) for pat in allow_destroy)
        if crit and not allowed:
            sev = crit
            if kind == "replace":
                msg = ("%s will be REPLACED (destroyed then recreated); data and identity attached to the "
                       "old object are lost" % rtype)
                fix = ("Find the attribute forcing replacement (see `replace_paths`/`terraform show`), "
                       "revert it, or use a snapshot, `terraform state mv` or `moved` block; if intended, "
                       "re-run with --allow-destroy %s" % rtype)
                rule = "PG-REPLACE"
            else:
                msg = "%s will be DESTROYED" % rtype
                fix = ("Confirm a backup/snapshot exists, remove the resource from the plan or use "
                       "`terraform state rm` if it must survive; if intended, re-run with "
                       "--allow-destroy %s" % rtype)
                rule = "PG-DESTROY"
            findings.append(Finding(rule, sev, address, msg, fix))
        # skip_final_snapshot on database delete
        if kind in ("delete", "replace") and not allowed and before.get("skip_final_snapshot") is True:
            findings.append(Finding(
                "PG-DESTROY", 3, address, "%s is deleted with skip_final_snapshot=true: no last backup" % rtype,
                "Set skip_final_snapshot = false and a final_snapshot_identifier before destroying"))
        if before.get("force_destroy") is True and rtype.endswith("bucket") and not allowed:
            findings.append(Finding(
                "PG-DESTROY", 3, address, "bucket has force_destroy=true: objects are deleted with it",
                "Set force_destroy = false, or empty/back up the bucket deliberately first"))

    if kind in ("delete", "read", "no-op", "unknown"):
        # still check removal of encryption configuration
        if kind == "delete" and rtype == "aws_s3_bucket_server_side_encryption_configuration":
            findings.append(Finding(
                "PG-ENCRYPTION", 3, address, "bucket default encryption configuration is being removed",
                "Keep the encryption configuration resource, or confirm another default applies"))
        if kind == "delete" and rtype == "aws_s3_bucket_public_access_block":
            findings.append(Finding(
                "PG-S3-PUBLIC", 3, address, "S3 public access block is being removed",
                "Keep aws_s3_bucket_public_access_block with all four settings true"))
        return findings

    # open sensitive ports (only newly exposed)
    new_exp = exposures(rtype, after) - exposures(rtype, before)
    for src, port in sorted(new_exp):
        sev = 4 if port == "all ports" else 3
        findings.append(Finding(
            "PG-SG-OPEN", sev, address,
            "%s opened to %s on %s" % (rtype, src, port),
            "Restrict the source to a known CIDR, security group or VPN range; "
            "use SSM Session Manager/bastion instead of public admin ports",
            "source=%s port=%s" % (src, port)))

    # public S3
    acl = after.get("acl")
    if rtype in ("aws_s3_bucket", "aws_s3_bucket_acl") and isinstance(acl, str) \
            and acl in CIDR_BLOCK_ACLS and acl != before.get("acl"):
        findings.append(Finding(
            "PG-S3-PUBLIC", 4 if acl.startswith("public") else 3, address,
            "bucket ACL set to %s" % acl,
            "Use acl = \"private\", keep a public access block, and serve content through CloudFront with OAC",
            "acl=%s" % acl))
    if rtype == "aws_s3_bucket_public_access_block":
        for k in ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"):
            if after.get(k) is False and before.get(k) is not False:
                findings.append(Finding(
                    "PG-S3-PUBLIC", 4, address, "S3 public access block: %s = false" % k,
                    "Set %s = true unless this bucket is deliberately public and reviewed" % k, "%s=false" % k))
    if rtype == "aws_s3_bucket_policy" and policy_public(after.get("policy")) \
            and not policy_public(before.get("policy")):
        findings.append(Finding(
            "PG-S3-PUBLIC", 4, address,
            "bucket policy allows Principal \"*\" with no Condition",
            "Scope the principal to specific accounts/roles or add a Condition such as aws:SourceVpce or aws:PrincipalOrgID"))
    if rtype in ("google_storage_bucket_iam_member", "google_storage_bucket_iam_binding"):
        members = as_list(after.get("member")) + as_list(after.get("members"))
        if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
            findings.append(Finding(
                "PG-S3-PUBLIC", 4, address, "GCS bucket IAM grants access to allUsers/allAuthenticatedUsers",
                "Grant the role to specific identities or groups instead"))

    # encryption off
    for attr in ENC_ATTRS:
        if after.get(attr) is False:
            was_on = before.get(attr) is True
            if was_on or kind in ("create", "replace"):
                findings.append(Finding(
                    "PG-ENCRYPTION", 3 if was_on else 2, address,
                    "%s: %s is false%s" % (rtype, attr, " (was true)" if was_on else ""),
                    "Set %s = true (and a customer-managed kms_key_id if policy requires); "
                    "changing it on existing storage often forces replacement" % attr,
                    "%s=false" % attr))
    if after.get("enable_key_rotation") is False and (before.get("enable_key_rotation") is True):
        findings.append(Finding(
            "PG-ENCRYPTION", 2, address, "KMS key rotation switched off",
            "Keep enable_key_rotation = true"))

    # deletion protection off
    for attr in DELPROT_ATTRS:
        if before.get(attr) is True and after.get(attr) is False:
            findings.append(Finding(
                "PG-DELPROT", 3, address, "%s switched off (was true)" % attr,
                "Leave %s = true and add lifecycle { prevent_destroy = true }; "
                "disable only in a reviewed, separate change" % attr, "%s true->false" % attr))
    for attr in DELPROT_INVERSE:
        if before.get(attr) is True and after.get(attr) is False:
            findings.append(Finding(
                "PG-DELPROT", 2, address, "%s switched off (termination protection removed)" % attr,
                "Keep %s = true for instances that must not be terminated by accident" % attr))
    if after.get("force_destroy") is True and before.get("force_destroy") is not True \
            and rtype.endswith("bucket"):
        findings.append(Finding(
            "PG-DELPROT", 2, address, "force_destroy turned on: a destroy would delete all objects",
            "Keep force_destroy = false on buckets that hold data"))

    # public IP additions
    for attr in PUBLIC_IP_ATTRS:
        if after.get(attr) is True and before.get(attr) is not True:
            findings.append(Finding(
                "PG-PUBLIC-IP", 2, address, "%s = true: resource gets a public address" % attr,
                "Place it in a private subnet behind a load balancer/NAT unless public exposure is required",
                "%s=true" % attr))
    if kind in ("create", "replace") and rtype in ("aws_eip", "azurerm_public_ip"):
        findings.append(Finding(
            "PG-PUBLIC-IP", 1, address, "new public IP (%s) will be allocated" % rtype,
            "Confirm the address must be internet-facing"))
    if kind in ("create", "replace") and rtype == "google_compute_address" \
            and str(after.get("address_type", "EXTERNAL")).upper() == "EXTERNAL":
        findings.append(Finding("PG-PUBLIC-IP", 1, address, "new external IP will be reserved",
                                "Confirm the address must be internet-facing"))
    if rtype in ("google_compute_instance",) and kind in ("create", "replace", "update"):
        def has_access_config(a):
            return any(isinstance(ni, dict) and ni.get("access_config")
                       for ni in as_list(a.get("network_interface")))
        if has_access_config(after) and not has_access_config(before):
            findings.append(Finding(
                "PG-PUBLIC-IP", 2, address, "network_interface.access_config gives the instance an external IP",
                "Remove access_config and use Cloud NAT / IAP for access"))
    return findings


def summarize(plan):
    counts = {"add": 0, "change": 0, "delete": 0, "replace": 0, "read": 0, "no-op": 0}
    total = 0
    for rc in plan.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        k = action_kind(change.get("actions"))
        total += 1
        if k == "create":
            counts["add"] += 1
        elif k == "update":
            counts["change"] += 1
        elif k == "delete":
            counts["delete"] += 1
        elif k == "replace":
            counts["replace"] += 1
        elif k == "read":
            counts["read"] += 1
        else:
            counts["no-op"] += 1
    counts["total"] = total
    return counts


def analyze(plan, allow_destroy=()):
    findings = []
    for rc in plan.get("resource_changes") or []:
        try:
            findings.extend(check_resource(rc, list(allow_destroy)))
        except RecursionError:
            continue
    findings.sort(key=lambda f: (-f.severity, f.address, f.rule))
    return summarize(plan), findings


# --------------------------------------------------------------- CLI

def build_parser():
    p = argparse.ArgumentParser(
        prog="planguard",
        description="Report risky changes in a Terraform plan (JSON) before apply. Never runs terraform.",
        epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage or input error.")
    p.add_argument("plan", nargs="?", default="-",
                   help="plan JSON from `terraform show -json plan.out` (file, or - / omitted for stdin)")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="low",
                   help="lowest severity that makes the exit code 1 (default: low = any finding)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--allow-destroy", action="append", default=[], metavar="TYPE",
                   help="do not flag destroy/replace of this resource type (glob ok, repeatable)")
    p.add_argument("--version", action="version", version="planguard " + __version__)
    return p


def render_text(summary, findings, shown):
    lines = []
    lines.append("planguard: %d resource change(s): add %d, change %d, delete %d, replace %d"
                 % (summary["total"], summary["add"], summary["change"], summary["delete"], summary["replace"]))
    if not findings:
        lines.append("no risky changes found")
    for f in findings:
        lines.append("%-8s %-12s %s" % (SEV_NAMES[f.severity], f.rule, f.address))
        lines.append("         %s" % f.message)
        lines.append("         fix: %s" % f.fix)
    if findings and not shown:
        lines.append("(no finding at or above the --fail-on level)")
    return "\n".join(lines)


def main(argv=None, stdin=None, stdout=None):
    out = stdout if stdout is not None else sys.stdout
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as e:
        return 2 if e.code not in (0, None) else 0
    try:
        data = read_source(args.plan, stdin)
        plan = parse_plan(data)
        summary, findings = analyze(plan, args.allow_destroy)
    except PlanError as e:
        msg = "planguard: error: %s" % e
        if args.json:
            out.write(json.dumps({"tool": "planguard", "error": str(e), "exit": 2}) + "\n")
        sys.stderr.write(msg + "\n")
        return 2
    except RecursionError:
        sys.stderr.write("planguard: error: plan nested too deeply\n")
        return 2
    threshold = None if args.fail_on == "never" else SEV_ORDER[args.fail_on]
    failing = [f for f in findings if threshold is not None and f.severity >= threshold]
    code = 1 if failing else 0
    if args.json:
        out.write(json.dumps({
            "tool": "planguard", "version": __version__, "summary": summary,
            "fail_on": args.fail_on, "findings": [f.as_dict() for f in findings], "exit": code,
        }, indent=2) + "\n")
    else:
        out.write(render_text(summary, findings, bool(failing)) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main())
