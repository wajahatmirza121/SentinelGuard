import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

os.environ["SENTINEL_LOAD_DEMO"] = "1"

from sentinel import advisory, cli, config, hooks, netguard, notify, report, scanner      # noqa: E402
from sentinel.rules import php                                                             # noqa: E402
from sentinel.store import Store                                                           # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "vulnerable_app"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.proj = self.tmp / "proj"
        shutil.copytree(FIX, self.proj)
        self.state = self.tmp / "state"
        self.state.mkdir()
        os.environ["SENTINEL_STATE_DIR"] = str(self.state)
        self.cfg = config.load(self.proj)
        self.store = Store(self.state)

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self, **kw):
        return scanner.scan_project(self.proj, self.cfg, self.store, self.state, **kw)

    def ids(self, path=None):
        return {f.rule_id for f in self.store.open_findings() if path is None or f.path == path}


class DetectionTests(Base):
    def test_php_vulnerability_classes_detected(self):
        self.scan()
        want = {"PHP001", "PHP002", "PHP003", "PHP004", "PHP005", "PHP006", "PHP007", "PHP008", "PHP015", "PHP016"}
        self.assertTrue(want <= self.ids(), f"missing: {want - self.ids()}")

    def test_sanitized_code_is_clean(self):
        self.scan()
        self.assertEqual([], [f for f in self.store.open_findings() if f.path == "safe.php"])

    def test_dependency_and_runtime_findings(self):
        self.scan()
        self.assertTrue({"SENTINEL-DEMO-0001", "SENTINEL-DEMO-0002", "SENTINEL-DEMO-0003"} <= self.ids())

    def test_secrets_are_masked_and_placeholders_skipped(self):
        self.scan()
        sec = [f for f in self.store.open_findings() if f.rule_id.startswith("SEC")]
        self.assertTrue(sec)
        for f in sec:
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", f.snippet + f.message)  # sentinel:ignore
            self.assertNotIn("Sup3rS3cretPass", f.snippet + f.message)
        self.assertFalse(any("your_api_key_here" in f.snippet for f in sec))

    def test_config_checks(self):
        self.scan()




        self.assertIn("CFG001", self.ids())          # .env not in .gitignore


class SuppressionTests(Base):
    def test_inline_ignore_marker(self):
        (self.proj / "sup.php").write_text("<?php\necho $_GET['a'];\necho $_GET['b']; // sentinel:ignore intentional\n")
        self.scan()
        lines = sorted(f.line for f in self.store.open_findings() if f.path == "sup.php")
        self.assertEqual([2], lines)


class WatchTests(Base):
    def test_watch_reports_only_new_findings_after_a_save(self):
        import threading
        import time
        from sentinel import watcher

        def edit():
            time.sleep(0.5)
            (self.proj / "live.php").write_text("<?php echo $_GET['x'];")

        t = threading.Thread(target=edit)
        t.start()
        lines = []
        with contextlib.redirect_stdout(io.StringIO()):
            watcher.watch(self.proj, self.cfg, self.store, self.state, interval=0.25, max_cycles=8, out=lines.append)
        t.join()
        self.assertTrue(any("new: 1" in l for l in lines), lines)
        self.assertIn("live.php", {f.path for f in self.store.open_findings()})


class TaintUnitTests(unittest.TestCase):
    def test_sanitizers_are_class_specific(self):
        v = {}
        self.assertTrue(php.tainted_for("$_GET['a']", "sql", v))
        self.assertFalse(php.tainted_for("intval($_GET['a'])", "sql", v))
        self.assertFalse(php.tainted_for("(int)$_GET['a']", "sql", v))
        self.assertTrue(php.tainted_for("htmlspecialchars($_GET['a'])", "sql", v))   # does not protect SQL
        self.assertFalse(php.tainted_for("htmlspecialchars($_GET['a'])", "xss", v))
        self.assertTrue(php.tainted_for("mysqli_real_escape_string($c, $_GET['a'])", "xss", v))

    def test_taint_propagates_through_variables_and_concat(self):
        f = php.scan_php("<?php $a = $_GET['x']; $b = 'x' . $a; echo $b;", "t.php")
        self.assertEqual(["PHP002"], [x.rule_id for x in f])

    def test_single_quoted_variable_is_not_tainted(self):
        f = php.scan_php("<?php $a = $_GET['x']; echo '$a';", "t.php")
        self.assertEqual([], f)

    def test_comments_ignored(self):
        f = php.scan_php("<?php /* echo $_GET['x']; */ // echo $_GET['y'];\n# echo $_GET['z'];", "t.php")
        self.assertEqual([], f)


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        k = advisory.vkey
        self.assertLess(k("1.9.0"), k("1.10.0"))
        self.assertLess(k("2.0.0-rc1"), k("2.0.0"))
        self.assertEqual(k("1.0"), k("1.0.0"))
        self.assertLess(k("v1.2.3"), k("1.2.4"))

    def test_osv_ranges(self):
        rng = {"events": [{"introduced": "1.0.0"}, {"fixed": "1.4.2"}]}
        self.assertEqual((True, "1.4.2"), advisory.in_range("1.2.0", rng))
        self.assertEqual((False, None), advisory.in_range("1.4.2", rng))
        self.assertEqual((False, None), advisory.in_range("0.9.0", rng))


class LifecycleTests(Base):
    def test_incremental_scanning(self):
        r1 = self.scan()
        self.assertGreater(r1.changed, 0)
        r2 = self.scan()
        self.assertEqual(0, r2.changed)
        self.assertEqual(0, len(r2.new))
        (self.proj / "safe.php").write_text("<?php echo 'changed';")
        self.assertEqual(1, self.scan().changed)

    def test_fixed_new_and_stable_fingerprints(self):
        self.scan()
        src = (self.proj / "index.php").read_text()
        (self.proj / "index.php").write_text("\n\n\n" + src)          # shift all lines: must not look "new"
        self.assertEqual(0, len(self.scan().new))
        (self.proj / "index.php").write_text("<?php echo 'clean';")
        res = self.scan()
        self.assertGreaterEqual(len(res.fixed), 5)
        (self.proj / "extra.php").write_text("<?php echo $_GET['z'];")
        res = self.scan()
        self.assertEqual(["PHP002"], [f.rule_id for f in res.new])

    def test_ignore_and_notification_dedupe(self):
        self.scan()
        fp = [f for f in self.store.open_findings() if f.rule_id == "PHP008"][0].fingerprint
        self.assertEqual(1, self.store.ignore(fp, "test"))
        self.assertNotIn(fp, {f.fingerprint for f in self.store.open_findings()})
        with contextlib.redirect_stdout(io.StringIO()):
            first = notify.dispatch(self.cfg, self.state, self.store)
            second = notify.dispatch(self.cfg, self.state, self.store)
        self.assertGreater(first, 0)
        self.assertEqual(0, second)

    def test_new_cve_found_without_code_change(self):
        self.scan()
        (self.state / "advisories").mkdir(exist_ok=True)
        (self.state / "advisories" / "X.json").write_text(json.dumps({
            "id": "TEST-2026-1", "summary": "new advisory", "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"ecosystem": "Packagist", "name": "demo/safe-lib"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.1"}]}]}]}))
        res = scanner.monitor_only(self.proj, self.cfg, self.store, self.state)
        self.assertEqual(["TEST-2026-1"], [f.rule_id for f in res.new])


class TrustTests(Base):
    """These are the 'proof' tests behind the no-added-risk claim."""

    def test_scan_never_modifies_project_and_never_uses_network(self):
        before = cli.tree_hash(self.proj)
        with netguard.no_network() as net:
            self.scan(full=True)
            scanner.monitor_only(self.proj, self.cfg, self.store, self.state)
            findings = self.store.open_findings()
            for fmt in ("text", "markdown", "json", "sarif"):
                report.render(findings, fmt, lang="ur")
        self.assertEqual(before, cli.tree_hash(self.proj))
        self.assertEqual(0, net["count"])

    def test_network_denied_by_default_and_logged(self):
        with self.assertRaises(netguard.NetworkDisabled):
            netguard.fetch("https://example.com/x", self.cfg, self.state, "test")
        self.assertFalse(netguard.read_log(self.state)[-1]["allowed"])
        with self.assertRaises(netguard.NetworkDisabled):
            netguard.fetch("http://example.com/x", self.cfg, self.state, "test")   # plain http refused

    def test_state_lives_outside_project(self):
        self.scan()
        self.assertFalse((self.proj / "findings.db").exists())
        self.assertTrue((self.state / "findings.db").exists())

    def test_symlinks_are_not_followed(self):
        outside = self.tmp / "outside.php"
        outside.write_text("<?php echo $_GET['x'];")
        try:
            os_symlink = os.symlink
            os_symlink(outside, self.proj / "link.php")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.scan()
        self.assertEqual([], [f for f in self.store.open_findings() if f.path == "link.php"])

    def test_cli_verify_passes(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = cli.main(["verify", str(self.proj)])
        self.assertEqual(0, code, out.getvalue())

    def test_hook_install_is_exact_and_reversible(self):
        (self.proj / ".git" / "hooks").mkdir(parents=True)
        self.assertIn("installed", hooks.install_hook(self.proj))
        self.assertTrue((self.proj / ".git" / "hooks" / "pre-commit").exists())
        hooks.uninstall(self.proj)
        self.assertFalse((self.proj / ".git" / "hooks" / "pre-commit").exists())
        foreign = self.proj / ".git" / "hooks" / "pre-commit"
        foreign.write_text("#!/bin/sh\necho mine\n")
        self.assertIn("left untouched", hooks.install_hook(self.proj))
        hooks.uninstall(self.proj)
        self.assertTrue(foreign.exists())                  # never deletes a hook it did not create

    def test_hook_is_fail_open(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)                              # not a git repo
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(["hook", "pre-commit"]))
        finally:
            os.chdir(cwd)

    def test_config_is_data_only_and_unknown_keys_ignored(self):
        (self.proj / ".sentinel.toml").write_text('[scan]\nfail_on = "high"\n[evil]\ncmd = "rm -rf /"\n')
        cfg = config.load(self.proj)
        self.assertEqual("high", cfg["scan"]["fail_on"])
        self.assertNotIn("evil", cfg)

    def test_sarif_is_valid_json(self):
        self.scan()
        data = json.loads(report.render(self.store.open_findings(), "sarif"))
        self.assertEqual("2.1.0", data["version"])
        self.assertTrue(data["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()
