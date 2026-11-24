import argparse
import contextlib
import ipaddress
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import linux_network as net


TABLE = 18002
HOST_PRIORITY = 49
CORP_RETURN_PRIORITY = 17998
CORP_FORWARD_PRIORITY = 17999
MARK = 0xD5000000
MASK = 0xFF000000


def table_name(token):
    return "dvpn_" + token


def dns_interface(token):
    return "dvpnd" + token


def marker(token):
    return f'create table ip {table_name(token)} {{ comment "dual-vpn:{token}"; }}'


def _rollback(actions):
    if not actions:
        return
    errors = []
    for action in reversed(actions[1:]):
        try:
            action()
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise RuntimeError("Не удалось удалить ресурсы domain routes: " + "; ".join(errors))
    actions[0]()


def corp_rules(args):
    table = table_name(args.token)
    return "\n".join([
        marker(args.token),
        f"add chain ip {table} clear_mark {{ type filter hook prerouting priority mangle; policy accept; }}",
        f'add rule ip {table} clear_mark iifname "{args.uplink}" meta mark & 0x{MASK:08x} == 0x{MARK:08x} '
        "meta mark set (meta mark & 0x00ffffff)",
    ])


def corp_setup(args):
    nft = net.Nftables()
    table = table_name(args.token)
    net.check_available(TABLE, {CORP_RETURN_PRIORITY, CORP_FORWARD_PRIORITY})
    actions = []
    try:
        nft.run(corp_rules(args))
        actions.append(lambda: nft.run(f"delete table ip {table}"))
        net.add_route(TABLE, args.tunnel)
        actions.append(lambda: net.delete_route(TABLE, args.tunnel))
        net.add_rule(254, CORP_RETURN_PRIORITY, incoming=args.tunnel)
        actions.append(lambda: net.delete_rule(254, CORP_RETURN_PRIORITY, incoming=args.tunnel))
        net.add_rule(TABLE, CORP_FORWARD_PRIORITY, incoming=args.uplink)
        actions.append(lambda: net.delete_rule(TABLE, CORP_FORWARD_PRIORITY, incoming=args.uplink))
    except BaseException:
        _rollback(actions)
        raise


def corp_check(args):
    nft = net.Nftables()
    table = table_name(args.token)
    if not nft.owned(table, args.token):
        raise RuntimeError("Отсутствуют правила маршрутизации корпоративного контейнера")
    status, chain = nft.run(f"list chain ip {table} clear_mark", check=False)
    if status or f'iifname "{args.uplink}"' not in chain or "0xd5000000" not in chain or "meta mark set" not in chain:
        raise RuntimeError("Не снимается служебная метка перед корпоративным туннелем")
    if not net.route_present(TABLE, args.tunnel):
        raise RuntimeError("Отсутствует маршрут через корпоративный туннель")
    if not net.rule_present(254, CORP_RETURN_PRIORITY, incoming=args.tunnel):
        raise RuntimeError("Отсутствует правило обратного маршрута корпоративного туннеля")
    if not net.rule_present(TABLE, CORP_FORWARD_PRIORITY, incoming=args.uplink):
        raise RuntimeError("Отсутствует правило входящего корпоративного трафика")


def corp_cleanup(args):
    nft = net.Nftables()
    table = table_name(args.token)
    if not nft.owned(table, args.token):
        return
    net.delete_rule(TABLE, CORP_FORWARD_PRIORITY, incoming=args.uplink)
    net.delete_rule(254, CORP_RETURN_PRIORITY, incoming=args.tunnel)
    net.delete_route(TABLE, args.tunnel)
    nft.run(f"delete table ip {table}")


def host_rules(args):
    table = table_name(args.token)
    rules = [
        marker(args.token),
        f"add set ip {table} destinations {{ type ipv4_addr; }}",
        f"add chain ip {table} output {{ type route hook output priority mangle; policy accept; }}",
        f"add chain ip {table} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}",
        f"add chain ip {table} dns_input {{ type filter hook input priority filter; policy accept; }}",
    ]
    for chain in ("output", "prerouting"):
        for network in args.exclude:
            rules.append(f"add rule ip {table} {chain} ip daddr {network} return")
        for server in args.dns_server:
            for protocol in ("udp", "tcp"):
                rules.append(f"add rule ip {table} {chain} ip daddr {server} {protocol} dport 53 "
                             f"meta mark set ((meta mark & 0x00ffffff) | 0x{MARK:08x})")
        rules.append(f"add rule ip {table} {chain} ip daddr @destinations "
                     f"meta mark set ((meta mark & 0x00ffffff) | 0x{MARK:08x})")
    for protocol in ("udp", "tcp"):
        rules.append(f"add rule ip {table} dns_input ip daddr {args.dns_ip} "
                     f"ip saddr != {args.dns_ip} {protocol} dport 53 drop")
    return "\n".join(rules)


def host_cleanup(args):
    nft = net.Nftables()
    table = table_name(args.token)
    if not nft.owned(table, args.token):
        return
    net.delete_link(dns_interface(args.token))
    net.delete_rule(TABLE, HOST_PRIORITY, mark=MARK, mask=MASK)
    net.delete_route(TABLE, args.bridge, args.container_ip)
    nft.run(f"delete table ip {table}")


def host_check(args):
    import dbus

    nft = net.Nftables()
    if not nft.owned(table_name(args.token), args.token):
        raise RuntimeError("Отсутствует набор nftables для domain routes")
    if not net.rule_present(TABLE, HOST_PRIORITY, mark=MARK, mask=MASK):
        raise RuntimeError("Отсутствует правило маршрутизации доменов")
    if not net.route_present(TABLE, args.bridge, args.container_ip):
        raise RuntimeError("Отсутствует маршрут через корпоративный контейнер")
    index = socket.if_nametoindex(dns_interface(args.token))
    bus = dbus.SystemBus()
    root = bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
    manager = dbus.Interface(root, "org.freedesktop.resolve1.Manager")
    properties = dbus.Interface(root, "org.freedesktop.DBus.Properties")
    if conflicting_domains(properties.Get("org.freedesktop.resolve1.Manager", "Domains"), args.domain, index):
        raise RuntimeError("Конфликт доменов с другим DNS-интерфейсом")
    link = bus.get_object("org.freedesktop.resolve1", manager.GetLink(index))
    link_props = dbus.Interface(link, "org.freedesktop.DBus.Properties")
    dns = link_props.Get("org.freedesktop.resolve1.Link", "DNS")
    domains = link_props.Get("org.freedesktop.resolve1.Link", "Domains")
    if (socket.AF_INET, ipaddress.IPv4Address(args.dns_ip).packed) not in [(int(family), bytes(addr)) for family, addr in dns]:
        raise RuntimeError("DNS-интерфейс domain routes изменён")
    if not set(args.domain).issubset({str(domain) for domain, routing in domains if routing}):
        raise RuntimeError("DNS-домены domain routes изменены")


def dnsmasq_command(args):
    domains = f"/#/4#ip#{table_name(args.token)}#destinations"
    return [args.dnsmasq, "--no-daemon", "--conf-file=/dev/null", "--no-resolv", "--no-hosts",
            "--bind-interfaces", f"--listen-address={args.dns_ip}", "--cache-size=0", "--max-ttl=60",
            "--filter-AAAA", "--filter-rr=64,65", f"--nftset={domains}", "--log-facility=-",
            *[f"--server={server}" for server in args.dns_server]]


def _skip_name(data, offset):
    while True:
        if offset >= len(data):
            raise ValueError("Некорректный DNS-ответ")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise ValueError("Некорректный DNS-ответ")
            return offset + 2
        if length & 0xC0 or offset + 1 + length > len(data):
            raise ValueError("Некорректный DNS-ответ")
        offset += 1 + length
        if not length:
            return offset


def answer_addresses(data, query_id):
    if len(data) < 12:
        raise ValueError("Короткий DNS-ответ")
    ident, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", data)
    if ident != query_id or not flags & 0x8000 or flags & 0xF not in (0, 3):
        raise ValueError("Корпоративный DNS вернул ошибку")
    offset = 12
    for _ in range(questions):
        offset = _skip_name(data, offset) + 4
        if offset > len(data):
            raise ValueError("Некорректный DNS-вопрос")
    addresses = []
    for _ in range(answers):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Некорректный DNS-ответ")
        record_type, record_class, _, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + size > len(data):
            raise ValueError("Некорректный DNS-ответ")
        if record_type == 1 and record_class == 1 and size == 4:
            addresses.append(str(ipaddress.IPv4Address(data[offset:offset + size])))
        offset += size
    return addresses


def dns_probe(args, process, nft):
    ident = 0xD519
    name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in args.domain[0].split(".")) + b"\0"
    query = struct.pack("!HHHHHH", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dns_interface(args.token).encode("ascii") + b"\0")
        conn.settimeout(1)
        for _ in range(8):
            if process.poll() is not None:
                raise RuntimeError("dnsmasq завершился при запуске")
            try:
                conn.sendto(query, (str(args.dns_ip), 53))
                data, _ = conn.recvfrom(65535)
                addresses = answer_addresses(data, ident)
                _, output = nft.run(f"list set ip {table_name(args.token)} destinations")
                if any(address not in output for address in addresses):
                    raise RuntimeError("dnsmasq не добавил DNS-адрес в набор маршрутизации")
                return
            except (socket.timeout, ConnectionRefusedError):
                continue
    raise RuntimeError("Корпоративный DNS не ответил через dnsmasq")


def conflicting_domains(registered, domains, index):
    conflicts = []
    for link, name, _ in registered:
        name = str(name).lower().rstrip(".")
        if int(link) != index and name and any(name == domain or name.endswith("." + domain) for domain in domains):
            conflicts.append(name)
    return sorted(set(conflicts))


def configure_resolved(args, index):
    import dbus

    bus = dbus.SystemBus()
    obj = bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
    manager = dbus.Interface(obj, "org.freedesktop.resolve1.Manager")
    properties = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
    registered = properties.Get("org.freedesktop.resolve1.Manager", "Domains")
    conflicts = conflicting_domains(registered, args.domain, index)
    if conflicts:
        raise RuntimeError("Домены уже назначены другому DNS-интерфейсу: " + ", ".join(conflicts))
    for attempt in range(30):
        try:
            manager.GetLink(index)
            break
        except dbus.DBusException:
            if attempt == 29:
                raise
            time.sleep(0.1)
    address = dbus.ByteArray(ipaddress.IPv4Address(args.dns_ip).packed)
    manager.SetLinkDNS(index, dbus.Array([(dbus.Int32(socket.AF_INET), address)], signature="(iay)"))
    manager.SetLinkDefaultRoute(index, dbus.Boolean(False))
    manager.SetLinkLLMNR(index, "no")
    manager.SetLinkMulticastDNS(index, "no")
    manager.SetLinkDNSOverTLS(index, "no")
    manager.SetLinkDNSSEC(index, "no")
    domains = [(dbus.String(domain), dbus.Boolean(True)) for domain in args.domain]
    manager.SetLinkDomains(index, dbus.Array(domains, signature="(sb)"))
    manager.FlushCaches()
    return manager


def _start_dnsmasq(args):
    return subprocess.Popen(["/usr/sbin/chroot", "/dnsroot", *dnsmasq_command(args)])


def _stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def host_run(args):
    nft = net.Nftables()
    table = table_name(args.token)
    net.check_available(TABLE, {HOST_PRIORITY})
    actions = []
    process = None
    manager = None
    ready = False
    stopping = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopping.set())
    signal.signal(signal.SIGINT, lambda *_: stopping.set())
    try:
        nft.run(host_rules(args))
        actions.append(lambda: nft.run(f"delete table ip {table}"))
        net.add_route(TABLE, args.bridge, args.container_ip)
        actions.append(lambda: net.delete_route(TABLE, args.bridge, args.container_ip))
        net.add_rule(TABLE, HOST_PRIORITY, mark=MARK, mask=MASK)
        actions.append(lambda: net.delete_rule(TABLE, HOST_PRIORITY, mark=MARK, mask=MASK))
        index = net.add_dummy(dns_interface(args.token), args.dns_ip)
        actions.append(lambda: net.delete_link(dns_interface(args.token)))
        process = _start_dnsmasq(args)
        dns_probe(args, process, nft)
        manager = configure_resolved(args, index)
        ready = True
        print("DOMAIN_ROUTER_READY", flush=True)
        while not stopping.wait(1):
            if process.poll() is not None:
                print("dnsmasq остановился; восстанавливаем DNS, не отключая правила", file=sys.stderr, flush=True)
                time.sleep(1)
                if not stopping.is_set():
                    process = _start_dnsmasq(args)
    finally:
        if not ready or stopping.is_set():
            if manager is not None:
                with contextlib.suppress(Exception):
                    manager.RevertLink(index)
                    manager.FlushCaches()
            _stop_process(process)
            _rollback(actions)


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("corp-setup", "corp-cleanup", "corp-check", "host-run", "host-cleanup", "host-check"))
    parser.add_argument("--token", required=True)
    parser.add_argument("--bridge", default="docker0")
    parser.add_argument("--container-ip", default="0.0.0.0")
    parser.add_argument("--tunnel", default="etg_vpn")
    parser.add_argument("--uplink", default="eth0")
    parser.add_argument("--dns-ip", default="169.254.248.253")
    parser.add_argument("--dnsmasq", default="/usr/sbin/dnsmasq")
    parser.add_argument("--dns-server", action="append", default=[])
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--exclude", action="append", default=[])
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-f]{8}", args.token):
        parser.error("неверный идентификатор ресурсов")
    if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in (args.bridge, args.tunnel, args.uplink)):
        parser.error("неверное имя интерфейса")
    try:
        args.container_ip = ipaddress.IPv4Address(args.container_ip)
        args.dns_ip = ipaddress.IPv4Address(args.dns_ip)
        args.dns_server = [ipaddress.IPv4Address(server) for server in args.dns_server]
        args.exclude = [ipaddress.IPv4Network(network, strict=False) for network in args.exclude]
    except ValueError:
        parser.error("неверный IPv4-адрес или подсеть")
    if args.action in ("host-run", "host-check"):
        if not args.domain or (args.action == "host-run" and not args.dns_server):
            parser.error("нужны корпоративные DNS-серверы и домены маршрутизации")
        for domain in args.domain:
            if len(domain) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                            for label in domain.split(".")):
                parser.error("неверный DNS-домен")
    return args


def main(argv=None):
    args = parse_args(argv)
    try:
        {"corp-setup": corp_setup, "corp-cleanup": corp_cleanup, "corp-check": corp_check,
         "host-check": host_check, "host-run": host_run, "host-cleanup": host_cleanup}[args.action](args)
    except Exception as exc:
        print(f"Ошибка маршрутизации доменов: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
