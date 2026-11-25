import base64
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from xray_cli import cli
from xray_cli.config import ProfileError, build_xray_config, parse_vless, tunnel_routes
from xray_cli.platform import linux


UUID = "00000000-1111-4222-8333-444444444444"
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def example_uri(**changes):
    query = {
        "encryption": "none", "security": "reality", "type": "tcp", "fp": "firefox",
        "pbk": KEY, "sid": "a1b2c3d4e5f6", "sni": "example.org", "spx": "/test/path",
    }
    query.update(changes)
    return f"vless://{UUID}@example.org:14038?{urlencode(query)}#Laptop"


def attribute(kind, value):
    size = 4 + len(value)
    return struct.pack("=HH", size, kind) + value + b"\0" * ((-size) % 4)


class ProfileTests(unittest.TestCase):
    def test_import_and_private_repr(self):
        profile = parse_vless(example_uri())
        self.assertEqual(profile.host, "example.org")
        self.assertEqual(profile.port, 14038)
        self.assertEqual(profile.server_name, "example.org")
        self.assertEqual(profile.fingerprint, "firefox")
        self.assertEqual(profile.spider_x, "/test/path")
        self.assertEqual(profile.user_id, UUID)
        self.assertNotIn(UUID, repr(profile))
        self.assertNotIn(KEY, repr(profile))
        self.assertEqual(profile, type(profile).from_dict(asdict(profile)))

    def test_imports_mihomo_mlkem_hint_without_changing_xray_config(self):
        original = parse_vless(example_uri(flow="xtls-rprx-vision"))
        hint = {"support-x25519mlkem768": "true"}
        imported = parse_vless(example_uri(flow="xtls-rprx-vision", **hint))
        self.assertEqual(imported, original)
        self.assertEqual(
            build_xray_config(imported, "198.51.100.3", []),
            build_xray_config(original, "198.51.100.3", []),
        )

    def test_imports_mlkem_hint_from_stdin(self):
        uri = example_uri(**{"support-x25519mlkem768": "true"})
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, XDG_CONFIG_HOME=directory)
            result = subprocess.run(
                [sys.executable, str(cli.LAUNCHER), "import", "--stdin"],
                input=uri + "\n", text=True, capture_output=True, env=env, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(UUID, result.stdout + result.stderr)
            self.assertNotIn(KEY, result.stdout + result.stderr)
            path = Path(directory) / "xray-vpn" / "profile.json"
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            profile = json.loads(path.read_text())
            self.assertEqual(profile["user_id"], UUID)
            self.assertEqual(profile["public_key"], KEY)
            self.assertNotIn("support-x25519mlkem768", profile)

    def test_rejects_unenforceable_or_invalid_mlkem_hint(self):
        for value in ("false", "0", "", "invalid"):
            with self.subTest(value=value):
                uri = example_uri(**{"support-x25519mlkem768": value})
                with self.assertRaises(ProfileError) as error:
                    parse_vless(uri)
                self.assertIn("support-x25519mlkem768=true", str(error.exception))
                self.assertNotIn(UUID, str(error.exception))
                self.assertNotIn(KEY, str(error.exception))
        duplicate = example_uri(**{"support-x25519mlkem768": "true"}).replace(
            "#Laptop", "&support-x25519mlkem768=true#Laptop"
        )
        with self.assertRaises(ProfileError):
            parse_vless(duplicate)

    def test_reject_unsupported_or_malformed_profiles(self):
        bad = [
            example_uri(security="tls"),
            example_uri(type="ws"),
            example_uri(encryption="custom"),
            example_uri(flow="unknown"),
            example_uri(pbk="invalid"),
            example_uri(sid="abc"),
            example_uri(spx="relative"),
            example_uri(other="ignored"),
            example_uri().replace("#Laptop", "&security=tls#Laptop"),
            example_uri().replace(UUID, "invalid-uuid"),
            example_uri().replace("vless://", "vmess://"),
        ]
        for value in bad:
            with self.subTest(value=value.replace(UUID, "<uuid>").replace(KEY, "<key>")):
                with self.assertRaises(ProfileError) as error:
                    parse_vless(value)
                self.assertNotIn(UUID, str(error.exception))
                self.assertNotIn(KEY, str(error.exception))

    def test_saved_profile_revalidated(self):
        value = asdict(parse_vless(example_uri()))
        value["port"] = True
        with self.assertRaises(ProfileError):
            type(parse_vless(example_uri())).from_dict(value)
        value["port"] = 443
        value["user_id"] = "not-a-uuid"
        with self.assertRaises(ProfileError):
            type(parse_vless(example_uri())).from_dict(value)

    def test_private_atomic_file_and_symlink_directory(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "config"
            cli.private_directory(directory)
            target = directory / "profile.json"
            cli.atomic_json(target, asdict(parse_vless(example_uri())))
            self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(target.read_text())["user_id"], UUID)
            symlink = Path(root) / "link"
            symlink.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                cli.private_directory(symlink)


class RouteTests(unittest.TestCase):
    def test_exclusions_do_not_capture_gateway_or_local_networks(self):
        excluded = ["203.0.113.25/32", "192.168.31.0/24", "10.0.2.0/24", "10.0.2.1/32"]
        routes = [ipaddress.ip_network(value) for value in tunnel_routes(excluded)]
        for address in ("203.0.113.25", "192.168.31.100", "10.0.2.15"):
            self.assertFalse(any(ipaddress.ip_address(address) in route for route in routes), address)
        for address in ("203.0.113.24", "192.168.30.1", "1.1.1.1", "8.8.8.8"):
            self.assertTrue(any(ipaddress.ip_address(address) in route for route in routes), address)
        self.assertEqual(sum(route.num_addresses for route in routes), 2**32 - 1 - 256 - 256)
        with self.assertRaises(ValueError):
            tunnel_routes(["0.0.0.0/0"])

    def test_xray_config_keeps_all_reality_fields_and_protects_dns(self):
        profile = parse_vless(example_uri())
        config = build_xray_config(profile, "198.51.100.3", ["203.0.113.25/32", "192.168.31.0/24"])
        tun = config["inbounds"][0]["settings"]
        self.assertNotIn("autoSystemDnsToGateway", tun)
        self.assertEqual(tun["autoOutboundsInterface"], "auto")
        self.assertIn("::/0", tun["autoSystemRoutingTable"])
        routes = [ipaddress.ip_network(value) for value in tun["autoSystemRoutingTable"] if ":" not in value]
        for address in ("198.51.100.3", "203.0.113.25", "192.168.31.100", "198.18.0.2"):
            self.assertFalse(any(ipaddress.ip_address(address) in route for route in routes))
        reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["spiderX"], "/test/path")
        self.assertEqual(reality["publicKey"], KEY)
        self.assertEqual(reality["shortId"], "a1b2c3d4e5f6")
        self.assertEqual(config["outbounds"][1]["streamSettings"]["sockopt"]["dialerProxy"], "proxy")
        self.assertEqual(config["outbounds"][1]["settings"]["rules"], [{"action": "direct"}])
        self.assertEqual(config["log"]["access"], "none")
        no_ipv6 = build_xray_config(profile, "198.51.100.3", [], ipv6=False)["inbounds"][0]["settings"]
        self.assertFalse(any(":" in route for route in no_ipv6["autoSystemRoutingTable"]))
        self.assertEqual(no_ipv6["gateway"], ["198.18.0.1/30"])

    def test_proc_route_decoding(self):
        data = (
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            "wlan0 00000000 011FA8C0 0003 0 0 600 00000000 0 0 0\n"
            "wlan0 001FA8C0 00000000 0001 0 0 600 00FFFFFF 0 0 0\n"
        )
        routes = linux.parse_main_routes(data)
        self.assertEqual(str(routes[0][2]), "192.168.31.1")
        self.assertEqual(str(routes[1][1]), "192.168.31.0/24")
        self.assertEqual(routes[0][3], 600)

    def test_refuses_overlapping_tun_subnets(self):
        ipv4_routes = [("lan0", ipaddress.IPv4Network("198.18.0.0/15"), ipaddress.IPv4Address("0.0.0.0"), 0)]
        with self.assertRaises(RuntimeError):
            linux.validate_tun_networks(ipv4_routes, False)
        ipv6 = f"{int(ipaddress.IPv6Address('fd42:198:18::')):032x} 40 " + "0 " * 6 + "00000001 lan0\n"
        self.assertEqual(str(linux.parse_ipv6_routes(ipv6)[0]), "fd42:198:18::/64")
        with mock.patch.object(linux.Path, "read_text", return_value=ipv6):
            with self.assertRaises(RuntimeError):
                linux.validate_tun_networks([], True)

    def test_checkpoint_gateway_rule(self):
        header = struct.pack("=BBBBBBBBI", socket.AF_INET, 32, 0, 0, 0, 0, 0, 1, 2)
        attrs = (attribute(1, ipaddress.IPv4Address("203.0.113.25").packed)
                 + attribute(6, struct.pack("=I", 18000))
                 + attribute(15, struct.pack("=I", 18000)))
        ordinary_rule = struct.pack("=BBBBBBBBI", socket.AF_INET, 32, 0, 0, 0, 0, 0, 1, 0)
        rules = [(32, header + attrs), (32, ordinary_rule + attrs)]
        self.assertEqual([str(a) for a in linux.checkpoint_gateways_from_rules(rules)], ["203.0.113.25"])
        self.assertEqual(linux.checkpoint_gateways_from_rules([(32, ordinary_rule + attrs)]), [])

    @unittest.skipUnless(sys.platform == "linux", "netlink is Linux-specific")
    def test_native_route_query(self):
        self.assertEqual(linux.route_interface("127.0.0.1"), "lo")
        self.assertIsNotNone(linux.process_start_time(os.getpid()))


class LifecycleTests(unittest.TestCase):
    def test_detach_waits_for_new_session(self):
        with mock.patch.object(linux.os, "pipe", return_value=(10, 11)), \
             mock.patch.object(linux.os, "fork", return_value=123), \
             mock.patch.object(linux.os, "read", return_value=b"1") as read, \
             mock.patch.object(linux.os, "close"):
            self.assertFalse(linux.detach_worker())
            read.assert_called_once_with(10, 1)
        with mock.patch.object(linux.os, "pipe", return_value=(10, 11)), \
             mock.patch.object(linux.os, "fork", return_value=0), \
             mock.patch.object(linux.os, "setsid") as setsid, \
             mock.patch.object(linux.os, "write") as write, \
             mock.patch.object(linux.os, "close"):
            self.assertTrue(linux.detach_worker())
            setsid.assert_called_once()
            write.assert_called_once_with(11, b"1")

    def test_waits_for_detached_worker_after_sudo_exits(self):
        state = {"nonce": "a" * 32}
        platform = mock.Mock()
        platform.worker_matches.return_value = True
        platform.engine_matches.return_value = True
        platform.interface_exists.return_value = True
        platform.resolved_link_ready.return_value = True
        platform.route_interface.return_value = "xraycli0"
        sudo = mock.Mock()
        sudo.poll.return_value = 0
        with mock.patch.object(cli, "_linux", return_value=platform), \
             mock.patch.object(cli, "read_state", side_effect=[{}, state]), \
             mock.patch.object(cli.time, "sleep"):
            result = cli._wait_ready(Path("/tmp"), state["nonce"], sudo, {}, False)
        self.assertIs(result, state)

    def test_waits_for_routes_to_finish_installing(self):
        state = {"nonce": "a" * 32}
        platform = mock.Mock()
        platform.worker_matches.return_value = True
        platform.engine_matches.return_value = True
        platform.interface_exists.return_value = True
        platform.resolved_link_ready.return_value = True
        ipv6_routes = iter(["wan0", "xraycli0"])
        platform.route_interface.side_effect = lambda address: next(ipv6_routes) if ":" in address else "xraycli0"
        with mock.patch.object(cli, "_linux", return_value=platform), \
             mock.patch.object(cli, "read_state", return_value=state), \
             mock.patch.object(cli.time, "sleep"):
            result = cli._wait_ready(Path("/tmp"), state["nonce"], mock.Mock(), {}, True)
        self.assertIs(result, state)

    def test_passwordless_sudo_does_not_request_validation(self):
        with mock.patch.object(cli.os, "geteuid", return_value=1000), \
             mock.patch.object(cli.shutil, "which", return_value="/usr/bin/sudo"), \
             mock.patch.object(cli.subprocess, "run", return_value=mock.Mock(returncode=0)) as run:
            cli._sudo_validate()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ["sudo", "-n", "true"])

    def test_unknown_interface_is_not_removed(self):
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(linux, "interface_exists", return_value=True):
            with self.assertRaises(RuntimeError):
                cli._stop_locked(Path(root), {}, authenticate=False)

    def test_runtime_secret_removed_if_log_open_fails(self):
        platform = mock.Mock()
        platform.worker_matches.return_value = False
        platform.engine_matches.return_value = False
        platform.interface_exists.return_value = False
        platform.other_onexray_cores.return_value = []
        platform.onexray_gui_running.return_value = False
        platform.ipv6_enabled.return_value = False
        platform.main_routes.return_value = []
        platform.physical_interface.return_value = "eth0"
        platform.checkpoint_gateways.return_value = []
        platform.route_interface.return_value = "eth0"
        args = mock.Mock(core=None, bypass=[], skip_probe=True)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "state"
            directory.mkdir(mode=0o700)
            target = Path(root) / "other"
            target.write_text("untouched")
            (directory / "xray.log").symlink_to(target)
            with mock.patch.object(cli, "_linux", return_value=platform), \
                 mock.patch.object(cli, "state_dir", return_value=directory), \
                 mock.patch.object(cli, "load_profile", return_value=parse_vless(example_uri())), \
                 mock.patch.object(cli, "find_core", return_value="/bin/false"), \
                 mock.patch.object(cli, "_resolve_server", return_value="198.51.100.3"):
                with self.assertRaises(OSError):
                    cli.start(args)
            self.assertFalse((directory / "runtime.json").exists())
            self.assertEqual(target.read_text(), "untouched")

    def test_reject_stale_or_unrelated_pid(self):
        self.assertFalse(linux.worker_matches({"pid": os.getpid(), "start_time": 0, "nonce": "a" * 32}))
        self.assertFalse(linux.engine_matches({}, "/tmp"))
        self.assertFalse(linux.process_owns_interface(os.getpid(), "not-a-real-tun"))

    def test_dns_configuration_uses_dbus_and_rolls_back(self):
        class DBusError(Exception):
            pass

        manager = mock.Mock()
        bus = mock.Mock()
        dbus = mock.Mock()
        dbus.DBusException = DBusError
        dbus.Interface.return_value = manager
        dbus.Int32.side_effect = int
        dbus.ByteArray.side_effect = bytes
        dbus.String.side_effect = str
        dbus.Boolean.side_effect = bool
        dbus.Array.side_effect = lambda value, signature: value
        with mock.patch.object(linux, "_resolved_bus", return_value=(dbus, bus)), \
             mock.patch.object(linux.socket, "if_nametoindex", return_value=7):
            linux.configure_resolved_link("xraycli0")
            manager.SetLinkDNS.assert_called_once_with(7, [(socket.AF_INET, bytes([198, 18, 0, 2]))])
            manager.SetLinkDomains.assert_called_once_with(7, [(".", True)])
            manager.SetLinkDefaultRoute.assert_called_once_with(7, True)
            manager.RevertLink.assert_not_called()
            manager.SetLinkDomains.side_effect = DBusError()
            with self.assertRaises(RuntimeError):
                linux.configure_resolved_link("xraycli0")
            manager.RevertLink.assert_called_once_with(7)


if __name__ == "__main__":
    unittest.main()
