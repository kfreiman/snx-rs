import ipaddress
import json
import socket
from argparse import Namespace
from pathlib import Path

from dual_vpn.providers.base import Ctx, ProviderStatus, VpnProvider


def _repo_root():
    return Path(__file__).resolve().parents[2].parent.parent


def _import_xray():
    root = str(_repo_root())
    if root not in __import__("sys").path:
        __import__("sys").path.insert(0, root)
    from xray_cli import cli

    return cli


class XrayProvider(VpnProvider):
    NAME = "xray"

    def __init__(self, name, cfg):
        super().__init__(name, cfg)
        self.cfg = cfg
        self._cli = None

    def _cli_mod(self):
        if self._cli is None:
            self._cli = _import_xray()
        return self._cli

    def _args(self, bypasses):
        cli = self._cli_mod()
        merged = list(self.cfg.bypass)
        for net in bypasses:
            if net not in merged:
                merged.append(net)
        return Namespace(core=self.cfg.core or None, bypass=[str(n) for n in merged], skip_probe=self.cfg.skip_probe)

    def _patched_profile(self):
        cli = self._cli_mod()
        from unittest import mock

        return mock.patch.object(cli, "config_dir", return_value=Path(self.cfg.profile).parent)

    def check(self, ctx):
        cli = self._cli_mod()
        linux = cli._linux()
        problems = []
        if not Path(self.cfg.profile).is_file():
            problems.append(f"нет profile.json: {self.cfg.profile}; выполните ./xray-vpn import")
        try:
            cli.find_core(self.cfg.core or None)
        except RuntimeError as exc:
            problems.append(str(exc))
        try:
            linux.require_resolved()
        except RuntimeError as exc:
            problems.append(str(exc))
        return problems

    def validate(self):
        self._cli_mod()

    def start(self, ctx, bypasses):
        cli = self._cli_mod()
        with self._patched_profile():
            cli.start(self._args(bypasses))
        return self.status(ctx)

    def stop(self, ctx):
        cli = self._cli_mod()
        with self._patched_profile():
            cli.stop(Namespace())

    def status(self, ctx):
        cli = self._cli_mod()
        linux = cli._linux()
        directory = cli.state_dir()
        state = cli.read_state(directory)
        interfaces = ["xraycli0"] if linux.interface_exists("xraycli0") else []
        if linux.worker_matches(state) and linux.engine_matches(state, directory) and linux.interface_exists("xraycli0"):
            return ProviderStatus(self.name, True, f"PID {state.get('engine_pid')}", interfaces, self.endpoints(ctx))
        if linux.engine_matches(state, directory):
            return ProviderStatus(self.name, False, "orphaned core; нужен stop", interfaces, [])
        return ProviderStatus(self.name, False, "не запущен", interfaces, [])

    def endpoints(self, ctx):
        result = self._runtime_endpoints()
        try:
            profile = _read_profile(self.cfg.profile)
            infos = socket.getaddrinfo(profile.host, profile.port, socket.AF_INET, socket.SOCK_STREAM)
        except Exception:
            return result
        for info in infos:
            try:
                address = ipaddress.IPv4Address(info[4][0])
            except ValueError:
                continue
            if address not in result:
                result.append(address)
        return result

    def _runtime_endpoints(self):
        try:
            cli = self._cli_mod()
            directory = cli.state_dir()
            state = cli.read_state(directory)
            linux = cli._linux()
            if not linux.worker_matches(state) or not linux.engine_matches(state, directory):
                return []
            runtime = json.loads((directory / "runtime.json").read_text(encoding="utf-8"))
            result = []
            for outbound in runtime.get("outbounds", []):
                if outbound.get("tag") != "proxy":
                    continue
                for node in outbound.get("settings", {}).get("vnext", []):
                    address = ipaddress.IPv4Address(node["address"])
                    if address not in result:
                        result.append(address)
            return result
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return []

    def interfaces(self, ctx):
        return ["xraycli0"]

    def owns_default_route(self):
        return True

    def probe(self, ctx):
        from xray_cli.platform import linux
        if linux.route_interface("1.1.1.1") != "xraycli0":
            raise RuntimeError("1.1.1.1 не идёт через xraycli0")
        return True


def _read_profile(path):
    from xray_cli.config import Profile

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Profile.from_dict(data)
