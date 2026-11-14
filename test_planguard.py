import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

import planguard as pg

HERE = os.path.dirname(os.path.abspath(__file__))


def rc(rtype, actions, before=None, after=None, name="x", bs=None, as_=None, mode="managed"):
    return {
        "address": "%s.%s" % (rtype, name), "mode": mode, "type": rtype, "name": name,
        "change": {"actions": actions, "before": before, "after": after,
                   "before_sensitive": bs or {}, "after_sensitive": as_ or {}},
    }


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


def run(p, allow=()):
    s, f = pg.analyze(p, allow)
    return s, f


def rules(f):
    return [x.rule for x in f]


def cli(argv, stdin_text=None):
    out = io.StringIO()
    stdin = io.BytesIO(stdin_text.encode() if isinstance(stdin_text, str) else (stdin_text or b""))
    code = pg.main(argv, stdin=stdin, stdout=out)
    return code, out.getvalue()


class TestSummary(unittest.TestCase):
    def test_counts(self):
        p = plan(rc("aws_instance", ["create"], None, {}),
                 rc("aws_instance", ["update"], {}, {}, name="b"),
                 rc("aws_instance", ["delete"], {}, None, name="c"),
                 rc("aws_instance", ["delete", "create"], {}, {}, name="d"),
                 rc("aws_instance", ["no-op"], {}, {}, name="e"))
        s, _ = run(p)
        self.assertEqual((s["add"], s["change"], s["delete"], s["replace"], s["no-op"], s["total"]),
                         (1, 1, 1, 1, 1, 5))

    def test_create_before_destroy_is_replace(self):
        self.assertEqual(pg.action_kind(["create", "delete"]), "replace")

    def test_empty_plan(self):
        s, f = run({"format_version": "1.2"})
        self.assertEqual(s["total"], 0)
        self.assertEqual(f, [])

    def test_null_resource_changes(self):
        s, f = run({"format_version": "1.2", "resource_changes": None})
        self.assertEqual(s["total"], 0)

    def test_read_actions_not_counted_as_change(self):
        s, _ = run(plan(rc("aws_ami", ["read"], {}, {}, mode="data")))
        self.assertEqual(s["add"] + s["change"] + s["delete"], 0)


class TestDestroy(unittest.TestCase):
    def test_db_delete_critical(self):
        _, f = run(plan(rc("aws_db_instance", ["delete"], {"engine": "mysql"}, None)))
        self.assertEqual(rules(f), ["PG-DESTROY"])
        self.assertEqual(f[0].severity, 4)

    def test_db_replace(self):
        _, f = run(plan(rc("aws_db_instance", ["delete", "create"], {}, {})))
        self.assertIn("PG-REPLACE", rules(f))

    def test_bucket_kms_zone_iam_vpc(self):
        for t in ("aws_s3_bucket", "aws_kms_key", "aws_route53_zone", "aws_iam_role", "aws_vpc",
                  "aws_ebs_volume", "google_sql_database_instance"):
            _, f = run(plan(rc(t, ["delete"], {}, None)))
            self.assertEqual(rules(f), ["PG-DESTROY"], t)

    def test_noncritical_delete_ignored(self):
        _, f = run(plan(rc("aws_instance", ["delete"], {}, None)))
        self.assertEqual(f, [])

    def test_allow_destroy_exact(self):
        _, f = run(plan(rc("aws_s3_bucket", ["delete"], {}, None)), ["aws_s3_bucket"])
        self.assertEqual(f, [])

    def test_allow_destroy_glob(self):
        _, f = run(plan(rc("aws_iam_role", ["delete"], {}, None)), ["aws_iam_*"])
        self.assertEqual(f, [])

    def test_allow_destroy_other_type_still_flags(self):
        _, f = run(plan(rc("aws_s3_bucket", ["delete"], {}, None)), ["aws_vpc"])
        self.assertEqual(len(f), 1)

    def test_skip_final_snapshot(self):
        _, f = run(plan(rc("aws_db_instance", ["delete"], {"skip_final_snapshot": True}, None)))
        self.assertEqual(len(f), 2)

    def test_force_destroy_bucket_delete(self):
        _, f = run(plan(rc("aws_s3_bucket", ["delete"], {"force_destroy": True}, None)))
        self.assertEqual(len(f), 2)

    def test_data_source_ignored(self):
        _, f = run(plan(rc("aws_s3_bucket", ["delete"], {}, None, mode="data")))
        self.assertEqual(f, [])

    def test_create_of_critical_not_flagged(self):
        _, f = run(plan(rc("aws_s3_bucket", ["create"], None, {"bucket": "b"})))
        self.assertEqual(f, [])


class TestSecurityGroups(unittest.TestCase):
    def sg(self, ingress, before=None):
        return plan(rc("aws_security_group", ["create"] if before is None else ["update"],
                       before, {"ingress": ingress}))

    def test_ssh_open(self):
        _, f = run(self.sg([{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]))
        self.assertEqual(rules(f), ["PG-SG-OPEN"])
        self.assertIn("22/SSH", f[0].message)

    def test_ipv6_open(self):
        _, f = run(self.sg([{"from_port": 3389, "to_port": 3389, "protocol": "tcp",
                             "cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]}]))
        self.assertEqual(len(f), 1)

    def test_all_protocols_critical(self):
        _, f = run(self.sg([{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]))
        self.assertEqual(f[0].severity, 4)

    def test_http_open_not_flagged(self):
        _, f = run(self.sg([{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]))
        self.assertEqual(f, [])

    def test_private_cidr_not_flagged(self):
        _, f = run(self.sg([{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]))
        self.assertEqual(f, [])

    def test_range_includes_db_ports(self):
        _, f = run(self.sg([{"from_port": 3000, "to_port": 6500, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]))
        self.assertTrue(any("5432" in x.message for x in f) or any("3306" in x.message for x in f))

    def test_preexisting_exposure_not_reported(self):
        rule = {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}
        _, f = run(self.sg([rule], before={"ingress": [rule]}))
        self.assertEqual(f, [])

    def test_sg_rule_resource(self):
        _, f = run(plan(rc("aws_security_group_rule", ["create"], None,
                           {"type": "ingress", "from_port": 6379, "to_port": 6379, "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"]})))
        self.assertEqual(rules(f), ["PG-SG-OPEN"])

    def test_sg_egress_rule_ignored(self):
        _, f = run(plan(rc("aws_security_group_rule", ["create"], None,
                           {"type": "egress", "from_port": 22, "to_port": 22, "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"]})))
        self.assertEqual(f, [])

    def test_vpc_ingress_rule(self):
        _, f = run(plan(rc("aws_vpc_security_group_ingress_rule", ["create"], None,
                           {"cidr_ipv4": "0.0.0.0/0", "from_port": 27017, "to_port": 27017, "ip_protocol": "tcp"})))
        self.assertEqual(len(f), 1)

    def test_gcp_firewall(self):
        _, f = run(plan(rc("google_compute_firewall", ["create"], None,
                           {"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"],
                            "allow": [{"protocol": "tcp", "ports": ["22", "80"]}]})))
        self.assertEqual(rules(f), ["PG-SG-OPEN"])

    def test_gcp_firewall_port_range(self):
        _, f = run(plan(rc("google_compute_firewall", ["create"], None,
                           {"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["3000-3400"]}]})))
        self.assertEqual(len(f), 2)

    def test_azure_rule(self):
        _, f = run(plan(rc("azurerm_network_security_rule", ["create"], None,
                           {"direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                            "source_address_prefix": "*", "destination_port_range": "22"})))
        self.assertEqual(rules(f), ["PG-SG-OPEN"])

    def test_azure_deny_not_flagged(self):
        _, f = run(plan(rc("azurerm_network_security_rule", ["create"], None,
                           {"direction": "Inbound", "access": "Deny", "protocol": "Tcp",
                            "source_address_prefix": "*", "destination_port_range": "22"})))
        self.assertEqual(f, [])

    def test_garbage_port_values_do_not_crash(self):
        _, f = run(self.sg([{"from_port": "abc", "to_port": None, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]))
        self.assertIsInstance(f, list)


class TestS3Public(unittest.TestCase):
    def test_acl_public_read(self):
        _, f = run(plan(rc("aws_s3_bucket_acl", ["create"], None, {"acl": "public-read"})))
        self.assertEqual(rules(f), ["PG-S3-PUBLIC"])

    def test_acl_private_ok(self):
        _, f = run(plan(rc("aws_s3_bucket_acl", ["create"], None, {"acl": "private"})))
        self.assertEqual(f, [])

    def test_public_access_block_false(self):
        _, f = run(plan(rc("aws_s3_bucket_public_access_block", ["update"],
                           {"block_public_acls": True}, {"block_public_acls": False})))
        self.assertEqual(len(f), 1)

    def test_public_access_block_removed(self):
        _, f = run(plan(rc("aws_s3_bucket_public_access_block", ["delete"], {}, None)))
        self.assertEqual(rules(f), ["PG-S3-PUBLIC"])

    def test_public_policy(self):
        pol = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                                         "Resource": "arn:aws:s3:::b/*"}]})
        _, f = run(plan(rc("aws_s3_bucket_policy", ["create"], None, {"policy": pol})))
        self.assertEqual(rules(f), ["PG-S3-PUBLIC"])

    def test_policy_with_condition_ok(self):
        pol = json.dumps({"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject",
                                        "Resource": "*", "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}})
        _, f = run(plan(rc("aws_s3_bucket_policy", ["create"], None, {"policy": pol})))
        self.assertEqual(f, [])

    def test_bad_policy_json_no_crash(self):
        _, f = run(plan(rc("aws_s3_bucket_policy", ["create"], None, {"policy": "{not json"})))
        self.assertEqual(f, [])

    def test_gcs_all_users(self):
        _, f = run(plan(rc("google_storage_bucket_iam_member", ["create"], None,
                           {"member": "allUsers", "role": "roles/storage.objectViewer"})))
        self.assertEqual(len(f), 1)


class TestEncryptionDelprotPublicIp(unittest.TestCase):
    def test_encryption_turned_off(self):
        _, f = run(plan(rc("aws_db_instance", ["update"], {"storage_encrypted": True}, {"storage_encrypted": False})))
        self.assertEqual(rules(f), ["PG-ENCRYPTION"])
        self.assertEqual(f[0].severity, 3)

    def test_created_unencrypted_volume(self):
        _, f = run(plan(rc("aws_ebs_volume", ["create"], None, {"encrypted": False})))
        self.assertEqual(f[0].severity, 2)

    def test_encrypted_true_ok(self):
        _, f = run(plan(rc("aws_ebs_volume", ["create"], None, {"encrypted": True})))
        self.assertEqual(f, [])

    def test_encryption_config_removed(self):
        _, f = run(plan(rc("aws_s3_bucket_server_side_encryption_configuration", ["delete"], {}, None)))
        self.assertEqual(rules(f), ["PG-ENCRYPTION"])

    def test_key_rotation_off(self):
        _, f = run(plan(rc("aws_kms_key", ["update"], {"enable_key_rotation": True}, {"enable_key_rotation": False})))
        self.assertEqual(rules(f), ["PG-ENCRYPTION"])

    def test_deletion_protection_off(self):
        _, f = run(plan(rc("aws_db_instance", ["update"], {"deletion_protection": True}, {"deletion_protection": False})))
        self.assertEqual(rules(f), ["PG-DELPROT"])

    def test_deletion_protection_new_false_not_flagged(self):
        _, f = run(plan(rc("aws_db_instance", ["create"], None, {"deletion_protection": False})))
        self.assertEqual(f, [])

    def test_termination_protection_off(self):
        _, f = run(plan(rc("aws_instance", ["update"], {"disable_api_termination": True},
                           {"disable_api_termination": False})))
        self.assertEqual(rules(f), ["PG-DELPROT"])

    def test_force_destroy_turned_on(self):
        _, f = run(plan(rc("aws_s3_bucket", ["update"], {"force_destroy": False}, {"force_destroy": True})))
        self.assertEqual(rules(f), ["PG-DELPROT"])

    def test_public_ip_added(self):
        _, f = run(plan(rc("aws_instance", ["create"], None, {"associate_public_ip_address": True})))
        self.assertEqual(rules(f), ["PG-PUBLIC-IP"])

    def test_rds_publicly_accessible(self):
        _, f = run(plan(rc("aws_db_instance", ["update"], {"publicly_accessible": False},
                           {"publicly_accessible": True})))
        self.assertEqual(rules(f), ["PG-PUBLIC-IP"])

    def test_eip(self):
        _, f = run(plan(rc("aws_eip", ["create"], None, {})))
        self.assertEqual(f[0].severity, 1)

    def test_gcp_access_config(self):
        _, f = run(plan(rc("google_compute_instance", ["create"], None,
                           {"network_interface": [{"access_config": [{}]}]})))
        self.assertEqual(rules(f), ["PG-PUBLIC-IP"])


class TestRedaction(unittest.TestCase):
    def test_sensitive_mask_redacts(self):
        out = pg.scrub({"password": "hunter2", "name": "n", "nested": {"v": "s3cret"}},
                       {"nested": {"v": True}})
        self.assertEqual(out["nested"]["v"], pg.REDACTED)
        self.assertEqual(out["password"], pg.REDACTED)
        self.assertEqual(out["name"], "n")

    def test_whole_attr_sensitive(self):
        self.assertEqual(pg.scrub({"ingress": [1, 2]}, {"ingress": True})["ingress"], pg.REDACTED)

    def test_list_mask(self):
        out = pg.scrub({"l": ["a", "b"]}, {"l": [False, True]})
        self.assertEqual(out["l"], ["a", pg.REDACTED])

    def test_secret_never_in_output(self):
        p = plan(rc("aws_security_group", ["create"], None,
                    {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp",
                                  "cidr_blocks": ["0.0.0.0/0"], "description": "TOPSECRETVALUE"}]},
                    as_={"ingress": [{"description": True}]}))
        code, out = cli(["--json"], json.dumps(p))
        self.assertEqual(code, 1)
        self.assertNotIn("TOPSECRETVALUE", out)

    def test_sensitive_acl_not_leaked(self):
        p = plan(rc("aws_s3_bucket_acl", ["create"], None, {"acl": "public-read"}, as_={"acl": True}))
        _, f = run(p)
        self.assertEqual(f, [])  # redacted value cannot be judged, and is never echoed


class TestHostile(unittest.TestCase):
    def test_control_chars_in_address_sanitised(self):
        r = rc("aws_s3_bucket", ["delete"], {}, None)
        r["address"] = "aws_s3_bucket.evil\x1b[31m\nINJECT‮"
        code, out = cli([], json.dumps(plan(r)))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)
        self.assertEqual(len([l for l in out.splitlines() if l.startswith("INJECT")]), 0)

    def test_garbage_entries_in_resource_changes(self):
        p = plan(None, 5, "x", {"change": None}, {"type": 7, "change": {"actions": "delete"}}, [])
        s, f = run(p)
        self.assertEqual(f, [])

    def test_deep_nesting(self):
        text = "[" * 100000 + "]" * 100000
        code, _ = cli([], text)
        self.assertEqual(code, 2)

    def test_binary_input(self):
        code, _ = cli([], b"\xff\xfe\x00\x01garbage")
        self.assertEqual(code, 2)

    def test_not_json(self):
        self.assertEqual(cli([], "hello")[0], 2)

    def test_json_non_plan(self):
        self.assertEqual(cli([], '{"a": 1}')[0], 2)

    def test_json_list(self):
        self.assertEqual(cli([], "[1,2]")[0], 2)

    def test_resource_changes_wrong_type(self):
        self.assertEqual(cli([], '{"format_version":"1","resource_changes":{}}')[0], 2)

    def test_size_cap(self):
        old = pg.MAX_BYTES
        pg.MAX_BYTES = 10
        try:
            code, _ = cli([], '{"format_version": "1.2", "pad": "xxxxxxxxxxxxxxxx"}')
        finally:
            pg.MAX_BYTES = old
        self.assertEqual(code, 2)

    def test_missing_file(self):
        self.assertEqual(cli(["/nonexistent/plan.json"])[0], 2)

    def test_directory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cli([d])[0], 2)

    def test_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fifo = os.path.join(d, "f")
            os.mkfifo(fifo)
            self.assertEqual(cli([fifo])[0], 2)

    def test_symlink_to_file_read_ok(self):
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "p.json")
            with open(real, "w") as fh:
                json.dump(plan(), fh)
            link = os.path.join(d, "l.json")
            os.symlink(real, link)
            self.assertEqual(cli([link])[0], 0)

    def test_dangling_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            link = os.path.join(d, "l.json")
            os.symlink(os.path.join(d, "nope"), link)
            self.assertEqual(cli([link])[0], 2)

    def test_bom_ok(self):
        self.assertEqual(cli([], b"\xef\xbb\xbf" + json.dumps(plan()).encode())[0], 0)


class TestCli(unittest.TestCase):
    def risky(self):
        return json.dumps(plan(rc("aws_eip", ["create"], None, {}),
                               rc("aws_db_instance", ["delete"], {}, None)))

    def test_clean_exit_0(self):
        code, out = cli([], json.dumps(plan(rc("aws_instance", ["create"], None, {}))))
        self.assertEqual(code, 0)
        self.assertIn("no risky changes", out)

    def test_findings_exit_1(self):
        self.assertEqual(cli([], self.risky())[0], 1)

    def test_fail_on_high_ignores_low(self):
        p = json.dumps(plan(rc("aws_eip", ["create"], None, {})))
        self.assertEqual(cli(["--fail-on", "high"], p)[0], 0)
        self.assertEqual(cli(["--fail-on", "low"], p)[0], 1)

    def test_fail_on_critical(self):
        self.assertEqual(cli(["--fail-on", "critical"], self.risky())[0], 1)

    def test_fail_on_never(self):
        self.assertEqual(cli(["--fail-on", "never"], self.risky())[0], 0)

    def test_json_shape(self):
        code, out = cli(["--json"], self.risky())
        d = json.loads(out)
        self.assertEqual(d["summary"]["delete"], 1)
        self.assertEqual(d["exit"], 1)
        self.assertTrue(all("fix" in f for f in d["findings"]))

    def test_allow_destroy_cli(self):
        code, _ = cli(["--allow-destroy", "aws_db_instance", "--fail-on", "high"], self.risky())
        self.assertEqual(code, 0)

    def test_bad_flag_exit_2(self):
        self.assertEqual(cli(["--nope"])[0], 2)

    def test_bad_fail_on_value(self):
        self.assertEqual(cli(["--fail-on", "bogus"])[0], 2)

    def test_file_argument(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            with open(path, "w") as fh:
                fh.write(self.risky())
            self.assertEqual(cli([path])[0], 1)

    def test_subprocess_stdin(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "planguard.py"), "--json"],
                           input=self.risky().encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(json.loads(r.stdout)["tool"], "planguard")

    def test_json_error_output(self):
        code, out = cli(["--json"], "nope")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["exit"], 2)

    def test_does_not_import_subprocess_to_run_terraform(self):
        with open(os.path.join(HERE, "planguard.py")) as fh:
            src = fh.read()
        self.assertNotIn("subprocess", src)
        self.assertNotIn("os.system", src)


if __name__ == "__main__":
    unittest.main()
