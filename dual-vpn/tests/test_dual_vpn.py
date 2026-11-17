import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dual-vpn"))
sys.path.insert(0, str(ROOT))

from dual_vpn.config import ConfigError, load_dual_config, parse_snx_docker_config
from dual_vpn.orchestrator import Orchestrator
from dual_vpn.providers.base import Ctx, ProviderStatus


class FakeProvider:
    def __init__(self, name, endpoints=(), fails=False, running=False):
        self.name = name
        self.NAME = name
        self._endpoints = list(endpoints)
        self._fails = fails
        self.running = running
        self.started_with = None
        self.stopped = False

    def check(self, ctx):
        return []

    def start(self, ctx, bypasses):
        self.started_with = list(bypasses)
        if self._fails:
            raise RuntimeError(f"{self.name} boom")
        self.running = True
        return ProviderStatus(self.name, True)

    def stop(self, ctx):
        self.stopped = True
        self.running = False
        return None

    def status(self, ctx):
        return ProviderStatus(self.name, self.running)

    @property
    def cfg(self):
        return type("Cfg", (), {"gateway_via": "default"})()

    @property
    def health_checked(self):
        return False

    def endpoints(self, ctx):
        return list(self._endpoints)

    def interfaces(self, ctx):
        return [f"{self.name}-if"]

    def owns_default_route(self):
        return self.name == "personal"

    def probe(self, ctx):
        return None


def _config(tmp):
    import dual_vpn.config as config_mod
    (tmp / "dual.yaml").write_text(
        "version: 1\n"
        "start_order: [corp, personal]\n"
        "providers:\n"
        "  personal: {type: xray, config: p.yaml}\n"
        "  corp: {type: snx-docker, config: c.yaml}\n",
        encoding="utf-8",
    )
    return load_dual_config(str(tmp / "dual.yaml"))


class ConfigTests(unittest.TestCase):
    def test_examples_load(self):
        cfg = load_dual_config(str(ROOT / "dual-vpn/config/dual-vpn.yaml.example"))
        self.assertEqual(cfg.start_order, ["personal", "corp"])
        self.assertEqual(cfg.providers["personal"].type, "xray")
        self.assertEqual(cfg.providers["corp"].type, "snx-docker")

    def test_secret_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dual.yaml"
            path.write_text("version: 1\nproviders:\n  a: {type: xray, password: hunter2}\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_dual_config(str(path))

    def test_bad_order_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dual.yaml"
            path.write_text("version: 1\nstart_order: [a]\nproviders:\n  a: {type: xray, config: p.yaml}\n  b: {type: xray, config: q.yaml}\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_dual_config(str(path))

    def test_snx_priority_guard(self):
        path = ROOT / "dual-vpn/config/corp-snx-docker.yaml.example"
        cfg = parse_snx_docker_config(str(path))
        self.assertEqual(cfg.rule_priority, 50)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "corp.yaml"
            bad.write_text("type: snx-docker\nserver_name: vpn.example\nlogin_type: x\nrule_priority: 1500\n", encoding="utf-8")
            with self.assertRaises(ConfigError):
                parse_snx_docker_config(str(bad))


class OrchestratorTests(unittest.TestCase):
    def _orch(self, tmp, fakes):
        cfg = _config(Path(tmp))
        with mock.patch("dual_vpn.orchestrator.build_provider", side_effect=lambda n, t, p: fakes[n]):
            return Orchestrator(cfg, Ctx(Path(tmp) / "state"))

    def test_order_and_bypass(self):
        with tempfile.TemporaryDirectory() as tmp:
            corp = FakeProvider("corp", endpoints=[ipaddress.IPv4Address("203.0.113.7")])
            personal = FakeProvider("personal")
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            with mock.patch.object(orch, "_probe"):
                started = orch.start()
            self.assertEqual(started, ["corp", "personal"])
            self.assertEqual(personal.started_with, [ipaddress.IPv4Network("203.0.113.7/32")])

    def test_rollback_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            corp = FakeProvider("corp")
            personal = FakeProvider("personal", fails=True)
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            stopped = []
            corp.stop = lambda ctx: stopped.append("corp")
            with mock.patch.object(orch, "_probe"):
                with self.assertRaises(RuntimeError):
                    orch.start()
            self.assertEqual(stopped, ["corp"])

    def test_dry_run_does_not_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            corp = FakeProvider("corp")
            personal = FakeProvider("personal")
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            with mock.patch.object(orch, "doctor", return_value=[]):
                orch.start(dry_run=True)
            self.assertIsNone(corp.started_with)
            self.assertIsNone(personal.started_with)

    def test_pre_running_not_rolled_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            corp = FakeProvider("corp")
            personal = FakeProvider("personal", running=True, fails=True)
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            with mock.patch.object(orch, "_probe"):
                with self.assertRaises(RuntimeError):
                    orch.start()
            self.assertTrue(corp.stopped)
            self.assertFalse(personal.stopped)

    def test_auth_pending_preserves_container(self):
        from dual_vpn.providers.snx_docker import AuthPendingError

        class PendingCorp(FakeProvider):
            def start(self, ctx, bypasses):
                self.running = True
                raise AuthPendingError("pending")

        with tempfile.TemporaryDirectory() as tmp:
            corp = PendingCorp("corp")
            personal = FakeProvider("personal", running=True)
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            with mock.patch.object(orch, "_probe"):
                with self.assertRaises(AuthPendingError):
                    orch.start()
            self.assertFalse(corp.stopped)
            self.assertFalse(personal.stopped)

    def test_health_probe_runs_after_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            corp = FakeProvider("corp")
            personal = FakeProvider("personal")
            orch = self._orch(tmp, {"corp": corp, "personal": personal})
            orch.cfg.health.url = "https://example.test/health"
            with mock.patch.object(orch, "doctor", return_value=[]), mock.patch.object(orch, "_probe"), \
                 mock.patch("dual_vpn.orchestrator.subprocess.run") as run:
                run.return_value.returncode = 1
                started = orch.start()
                self.assertEqual(sorted(started), ["corp", "personal"])
                run.assert_called_once()
                self.assertFalse(corp.stopped)
                self.assertFalse(personal.stopped)


class SnxDockerTests(unittest.TestCase):
    def test_gateway_default_not_pinned(self):
        from dual_vpn.config import parse_snx_docker_config
        from dual_vpn.providers.snx_docker import SnxDockerProvider

        provider = SnxDockerProvider("corp", parse_snx_docker_config(str(ROOT / "dual-vpn/config/corp-snx-docker.yaml.example")))
        self.assertEqual(provider.cfg.gateway_via, "default")
        self.assertEqual(provider.endpoints(Ctx(Path("/tmp"))), [])
        added = []
        provider._add_policy_route = lambda dest, via=None, dev=None, src=None: added.append(dest)
        provider._uplink = lambda dest: (_ for _ in ()).throw(AssertionError("uplink не должен вызываться"))
        provider._gateway_ip = "203.0.113.7"
        with mock.patch("dual_vpn.providers.snx_docker._ip", return_value=mock.Mock(stdout="", returncode=0)):
            provider._policy_gateway()
        self.assertEqual(added, [])

    def test_resolvectl_called_directly_not_via_ip(self):
        import dual_vpn.providers.snx_docker as snx

        with mock.patch.object(snx, "_sudo", return_value=[]), mock.patch.object(snx, "_run") as run:
            run.return_value.returncode = 0
            snx._resolvectl("dns", "docker0", "10.40.22.100")
        run.assert_called_once_with(["resolvectl", "dns", "docker0", "10.40.22.100"])

    def test_bridge_name_method_not_shadowed(self):
        from dual_vpn.config import parse_snx_docker_config
        from dual_vpn.providers.snx_docker import SnxDockerProvider

        provider = SnxDockerProvider("corp", parse_snx_docker_config(str(ROOT / "dual-vpn/config/corp-snx-docker.yaml.example")))
        self.assertTrue(callable(provider._bridge_name))
        self.assertIsNone(provider._bridge)
        with mock.patch.object(provider, "_docker_cmd") as cmd:
            cmd.return_value.stdout = ""
            cmd.return_value.returncode = 1
            self.assertEqual(provider._bridge_name(), "docker0")


if __name__ == "__main__":
    unittest.main()
