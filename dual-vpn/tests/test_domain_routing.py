import contextlib
import errno
import io
import ipaddress
import json
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "dual-vpn"))
sys.path.insert(0, str(ROOT / "dual-vpn/dual_vpn/platform"))

from dual_vpn.config import ConfigError, parse_snx_docker_config
from dual_vpn.domain_routing import DomainRouter, _mounts, _service
import domain_service as service
import linux_network as net


class DomainConfigTests(unittest.TestCase):
    def parse(self, lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corp.yaml"
            path.write_text("type: snx-docker\nserver_name: vpn.example\nlogin_type: login\n" + lines,
                            encoding="utf-8")
            return parse_snx_docker_config(path)

    def test_suffixes_are_normalized_and_deduplicated(self):
        config = self.parse("route_domains: [OVH.NET., ovh.net, S3.RBX.IO.CLOUD.OVH.NET]\n")
        self.assertEqual(config.route_domains, ["ovh.net", "s3.rbx.io.cloud.ovh.net"])

    def test_invalid_domains_are_rejected(self):
        for value in ("*.ovh.net", "ovh.net/4#ip#test", "x..ovh.net", "localhost", "1.2.3.4"):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.parse("route_domains: [" + json.dumps(value) + "]\n")

    def test_domain_routing_is_opt_in(self):
        self.assertEqual(self.parse("").route_domains, [])


class DnsRoutingTests(unittest.TestCase):
    def args(self):
        return service.parse_args(["host-run", "--token", "12345678", "--bridge", "docker0",
                                   "--container-ip", "172.17.0.2", "--dns-ip", "169.254.248.253",
                                   "--domain", "ovh.net", "--dns-server", "10.40.22.100",
                                   "--exclude", "172.17.0.0/16", "--exclude", "203.0.113.7/32"])

    def test_dns_command_routes_suffix_and_disables_ipv6_answers(self):
        command = service.dnsmasq_command(self.args())
        self.assertIn("--nftset=/#/4#ip#dvpn_12345678#destinations", command)
        self.assertIn("--filter-AAAA", command)
        self.assertIn("--filter-rr=64,65", command)
        self.assertIn("--cache-size=0", command)
        self.assertIn("--server=10.40.22.100", command)

    def test_nft_rules_mark_both_host_and_forwarded_packets_and_protect_dns(self):
        rules = service.host_rules(self.args())
        self.assertIn("type route hook output", rules)
        self.assertIn("hook prerouting", rules)
        self.assertIn("ip daddr 172.17.0.0/16 return", rules)
        self.assertIn("ip daddr 203.0.113.7/32 return", rules)
        self.assertIn("ip daddr 10.40.22.100 udp dport 53 meta mark set", rules)
        self.assertIn("ip daddr 10.40.22.100 tcp dport 53 meta mark set", rules)
        self.assertIn("0xd5000000", rules)
        self.assertIn("ip saddr != 169.254.248.253 udp dport 53 drop", rules)
        self.assertIn("ip saddr != 169.254.248.253 tcp dport 53 drop", rules)

    def test_a_answer_after_cname_is_read(self):
        name = b"\x05alias\x03ovh\x03net\0"
        question = name + struct.pack("!HH", 1, 1)
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.10")
        response = struct.pack("!HHHHHH", 123, 0x8180, 1, 2, 0, 0) + question + cname + answer
        self.assertEqual(service.answer_addresses(response, 123), ["203.0.113.10"])

    def test_dns_errors_and_truncation_are_rejected(self):
        servfail = struct.pack("!HHHHHH", 123, 0x8182, 0, 0, 0, 0)
        for data in (b"short", servfail, struct.pack("!HHHHHH", 123, 0x8180, 1, 0, 0, 0) + b"\xc0"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                service.answer_addresses(data, 123)

    def test_overlapping_dns_routes_are_rejected(self):
        domains = [(7, "s3.rbx.io.cloud.ovh.net", True), (8, "OVH.NET.", False),
                   (9, ".", True), (10, "etg.team", True)]
        self.assertEqual(service.conflicting_domains(domains, ["ovh.net"], 8), ["s3.rbx.io.cloud.ovh.net"])
        self.assertEqual(service.conflicting_domains(domains, ["ovh.net"], 11),
                         ["ovh.net", "s3.rbx.io.cloud.ovh.net"])
        self.assertEqual(service.conflicting_domains([(9, "net", True)], ["ovh.net"], 11), [])

    def test_helper_rejects_untrusted_nft_names(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                service.parse_args(["corp-setup", "--token", "x;bad"])
            with self.assertRaises(SystemExit):
                service.parse_args(["host-run", "--token", "12345678", "--domain", "x/y", "--dns-server", "10.0.0.1"])


class NetworkLifecycleTests(unittest.TestCase):
    def test_rule_encoding_preserves_mark_mask_and_priority(self):
        message = net.rule_message(18002, 49, mark=service.MARK, mask=service.MASK)
        attrs = dict(net.attributes(message[12:]))
        self.assertEqual(struct.unpack("=I", attrs[6])[0], 49)
        self.assertEqual(struct.unpack("=I", attrs[15])[0], 18002)
        self.assertEqual(struct.unpack("=I", attrs[10])[0], service.MARK)
        self.assertEqual(struct.unpack("=I", attrs[16])[0], service.MASK)

    def test_container_clears_only_the_domain_mark_before_encryption(self):
        args = service.parse_args(["corp-setup", "--token", "12345678", "--uplink", "eth0"])
        rules = service.corp_rules(args)
        self.assertIn('iifname "eth0"', rules)
        self.assertIn("meta mark & 0xff000000 == 0xd5000000", rules)
        self.assertIn("meta mark set (meta mark & 0x00ffffff)", rules)

    def test_container_setup_rolls_back_only_created_resources(self):
        args = service.parse_args(["corp-setup", "--token", "12345678"])
        nft = mock.Mock()
        with mock.patch.object(net, "Nftables", return_value=nft), mock.patch.object(net, "check_available"), \
             mock.patch.object(net, "add_route"), mock.patch.object(net, "delete_route") as delete_route, \
             mock.patch.object(net, "add_rule", side_effect=[None, OSError("failure")]), \
             mock.patch.object(net, "delete_rule") as delete_rule:
            with self.assertRaises(OSError):
                service.corp_setup(args)
        delete_rule.assert_called_once_with(254, service.CORP_RETURN_PRIORITY, incoming="etg_vpn")
        delete_route.assert_called_once_with(service.TABLE, "etg_vpn")
        self.assertEqual(nft.run.call_args_list[-1], mock.call("delete table ip dvpn_12345678"))

    def test_host_failure_does_not_remove_an_uncreated_link(self):
        args = DnsRoutingTests().args()
        nft = mock.Mock()
        with mock.patch.object(net, "Nftables", return_value=nft), mock.patch.object(net, "check_available"), \
             mock.patch.object(net, "add_route"), mock.patch.object(net, "delete_route") as delete_route, \
             mock.patch.object(net, "add_rule"), mock.patch.object(net, "delete_rule") as delete_rule, \
             mock.patch.object(net, "add_dummy", side_effect=RuntimeError("existing")), \
             mock.patch.object(net, "delete_link") as delete_link, mock.patch.object(service.signal, "signal"):
            with self.assertRaisesRegex(RuntimeError, "existing"):
                service.host_run(args)
        delete_link.assert_not_called()
        delete_rule.assert_called_once_with(service.TABLE, service.HOST_PRIORITY, mark=service.MARK, mask=service.MASK)
        delete_route.assert_called_once_with(service.TABLE, "docker0", ipaddress.IPv4Address("172.17.0.2"))
        self.assertEqual(nft.run.call_args_list[-1], mock.call("delete table ip dvpn_12345678"))

    def test_rollback_keeps_ownership_marker_when_cleanup_fails(self):
        marker = mock.Mock()
        failing = mock.Mock(side_effect=OSError("busy"))
        other = mock.Mock()
        with self.assertRaisesRegex(RuntimeError, "busy"):
            service._rollback([marker, failing, other])
        marker.assert_not_called()
        other.assert_called_once()

    def test_missing_interface_is_already_cleaned(self):
        with mock.patch.object(net, "route_message", side_effect=OSError(errno.ENXIO, "missing")):
            net.delete_route(18002, "gone")

    def test_cleanup_refuses_unowned_tables(self):
        args = service.parse_args(["corp-cleanup", "--token", "12345678"])
        nft = mock.Mock()
        nft.owned.return_value = False
        with mock.patch.object(net, "Nftables", return_value=nft), \
             mock.patch.object(net, "delete_route") as delete_route, mock.patch.object(net, "delete_rule") as delete_rule:
            service.corp_cleanup(args)
        delete_route.assert_not_called()
        delete_rule.assert_not_called()
        nft.run.assert_not_called()

    def test_existing_unowned_container_is_not_removed(self):
        provider = mock.Mock()
        provider.cfg = SimpleNamespace(container_name="vpn")
        provider._docker_cmd.return_value = SimpleNamespace(returncode=0, stdout='{"owner":"someone-else"}', stderr="")
        with self.assertRaisesRegex(RuntimeError, "не принадлежит"):
            DomainRouter(provider).stop()
        self.assertEqual(provider._docker_cmd.call_count, 1)

    def test_restarted_corporate_container_is_not_reported_healthy(self):
        provider = mock.Mock()
        provider.cfg = SimpleNamespace(container_name="vpn", route_domains=["ovh.net"])
        router = DomainRouter(provider)
        meta = {"token": "12345678", "corp_id": "old-id", "corp_started": "old-start",
                "container_ip": "172.17.0.2"}
        with mock.patch.object(router, "_labels", return_value={"owned": True}), \
             mock.patch.object(router, "_running", return_value=True), \
             mock.patch.object(router, "_metadata", return_value=meta), \
             mock.patch.object(router, "_corp_id", return_value="old-id"), \
             mock.patch.object(router, "_corp_started", return_value="new-start"):
            self.assertFalse(router.running())

    def test_active_xray_endpoint_is_kept_when_dns_changes(self):
        from dual_vpn.providers.xray import XrayProvider

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "runtime.json").write_text(json.dumps({"outbounds": [{"tag": "proxy", "settings": {
                "vnext": [{"address": "203.0.113.42"}]}}]}), encoding="utf-8")
            provider = XrayProvider("personal", SimpleNamespace(profile=directory / "profile.json"))
            cli = mock.Mock()
            cli.state_dir.return_value = directory
            cli._linux.return_value.worker_matches.return_value = True
            cli._linux.return_value.engine_matches.return_value = True
            with mock.patch.object(provider, "_cli_mod", return_value=cli), \
                 mock.patch("dual_vpn.providers.xray._read_profile", side_effect=OSError("DNS unavailable")):
                self.assertEqual(provider.endpoints(None), [ipaddress.IPv4Address("203.0.113.42")])

    def test_helper_does_not_mount_the_entire_host_filesystem(self):
        with mock.patch("dual_vpn.domain_routing.Path.exists", return_value=True):
            mounts = _mounts(bus=True)
        self.assertFalse(any("src=/,dst=" in arg for arg in mounts))
        self.assertTrue(any("dst=/host/dnsroot/usr" in arg for arg in mounts))
        self.assertFalse(any("dst=/host/dnsroot/run/dbus" in arg for arg in mounts))
        command = _service("host-run", "12345678", domain=["ovh.net"], dns_server=["10.40.22.100"])
        self.assertIn("ovh.net", command)
        self.assertIn("10.40.22.100", command)


if __name__ == "__main__":
    unittest.main()
