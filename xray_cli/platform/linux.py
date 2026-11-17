import errno
import ipaddress
import os
import socket
import struct
from pathlib import Path


_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_RTM_NEWROUTE = 24
_RTM_GETROUTE = 26
_RTM_NEWRULE = 32
_RTM_GETRULE = 34
_FIB_RULE_INVERT = 2


def _attributes(data):
    offset = 0
    while offset + 4 <= len(data):
        size, kind = struct.unpack_from("=HH", data, offset)
        if size < 4 or offset + size > len(data):
            raise RuntimeError("Некорректный ответ netlink")
        yield kind & 0x3FFF, data[offset + 4:offset + size]
        offset += (size + 3) & ~3
    if offset != len(data):
        raise RuntimeError("Некорректный ответ netlink")


def _netlink_request(kind, payload, dump=False):
    flags = 1 | (0x300 if dump else 0)
    header = struct.pack("=IHHII", 16 + len(payload), kind, flags, 1, 0)
    replies = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as conn:
        conn.settimeout(5)
        conn.bind((0, 0))
        conn.send(header + payload)
        while True:
            data = conn.recv(1024 * 1024)
            offset = 0
            while offset + 16 <= len(data):
                size, msg_type, _, seq, _ = struct.unpack_from("=IHHII", data, offset)
                if size < 16 or offset + size > len(data):
                    raise RuntimeError("Некорректный ответ netlink")
                body = data[offset + 16:offset + size]
                offset += (size + 3) & ~3
                if seq != 1:
                    continue
                if msg_type == _NLMSG_DONE:
                    return replies
                if msg_type == _NLMSG_ERROR:
                    if len(body) < 4:
                        raise RuntimeError("Некорректная ошибка netlink")
                    error = struct.unpack_from("=i", body)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    continue
                replies.append((msg_type, body))
                if not dump:
                    return replies
            if offset != len(data):
                raise RuntimeError("Некорректный ответ netlink")


def checkpoint_gateways_from_rules(messages):
    gateways = set()
    for msg_type, body in messages:
        if msg_type != _RTM_NEWRULE or len(body) < 12:
            continue
        family, dst_len, src_len, _, table, _, _, action, flags = struct.unpack_from("=BBBBBBBBI", body)
        if family != socket.AF_INET or dst_len != 32 or src_len != 0 or action != 1 or not flags & _FIB_RULE_INVERT:
            continue
        attrs = dict(_attributes(body[12:]))
        if len(attrs.get(6, b"")) != 4 or len(attrs.get(1, b"")) != 4:
            continue
        priority = struct.unpack("=I", attrs[6])[0]
        if 15 in attrs and len(attrs[15]) == 4:
            table = struct.unpack("=I", attrs[15])[0]
        if table == 18000 and priority == 18000:
            gateways.add(ipaddress.IPv4Address(attrs[1]))
    return sorted(gateways)


def checkpoint_gateways():
    rule = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0)
    return checkpoint_gateways_from_rules(_netlink_request(_RTM_GETRULE, rule, dump=True))


def parse_main_routes(text):
    routes = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            raise RuntimeError("Не удалось прочитать таблицу IPv4-маршрутов")
        try:
            interface, destination, gateway = fields[0:3]
            flags = int(fields[3], 16)
            metric = int(fields[6])
            mask = ipaddress.IPv4Address(int(fields[7], 16).to_bytes(4, "little"))
            address = ipaddress.IPv4Address(int(destination, 16).to_bytes(4, "little"))
            network = ipaddress.IPv4Network((address, str(mask)), strict=False)
            gateway = ipaddress.IPv4Address(int(gateway, 16).to_bytes(4, "little"))
        except (ValueError, OverflowError):
            raise RuntimeError("Не удалось прочитать таблицу IPv4-маршрутов") from None
        if flags & 1:
            routes.append((interface, network, gateway, metric))
    return routes


def main_routes():
    return parse_main_routes(Path("/proc/net/route").read_text())


def parse_ipv6_routes(text):
    routes = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10:
            raise RuntimeError("Не удалось прочитать таблицу IPv6-маршрутов")
        try:
            network = ipaddress.IPv6Network((int(fields[0], 16), int(fields[1], 16)), strict=False)
            flags = int(fields[8], 16)
        except ValueError:
            raise RuntimeError("Не удалось прочитать таблицу IPv6-маршрутов") from None
        if network.prefixlen and flags & 1:
            routes.append(network)
    return routes


def validate_tun_networks(routes, ipv6):
    ipv4_network = ipaddress.IPv4Network("198.18.0.0/30")
    if any(network.prefixlen and network.overlaps(ipv4_network) for _, network, _, _ in routes):
        raise RuntimeError("Сеть TUN 198.18.0.0/30 уже используется другим маршрутом")
    if ipv6:
        ipv6_network = ipaddress.IPv6Network("fd42:198:18::/126")
        ipv6_routes = parse_ipv6_routes(Path("/proc/net/ipv6_route").read_text())
        if any(network.overlaps(ipv6_network) for network in ipv6_routes):
            raise RuntimeError("Сеть TUN fd42:198:18::/126 уже используется другим маршрутом")


def physical_interface(routes, tunnel_interface):
    candidates = sorted(
        (metric, interface)
        for interface, network, _, metric in routes
        if network.prefixlen == 0 and interface not in (tunnel_interface, "lo")
    )
    for _, name in candidates:
        try:
            socket.if_nametoindex(name)
            return name
        except OSError:
            continue
    raise RuntimeError("Не найден физический IPv4-маршрут по умолчанию")


def route_interface(address):
    address = ipaddress.ip_address(address)
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    message = struct.pack("=BBBBBBBBI", family, address.max_prefixlen, 0, 0, 0, 0, 0, 0, 0)
    attribute = struct.pack("=HH", 4 + len(address.packed), 1) + address.packed
    responses = _netlink_request(_RTM_GETROUTE, message + attribute)
    for msg_type, body in responses:
        if msg_type == _RTM_NEWROUTE and len(body) >= 12:
            for kind, data in _attributes(body[12:]):
                if kind == 4 and len(data) == 4:
                    return socket.if_indextoname(struct.unpack("=I", data)[0])
    raise RuntimeError("Не удалось определить интерфейс маршрута")


def interface_exists(name):
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False


def _resolved_bus():
    try:
        import dbus
    except ImportError:
        raise RuntimeError("Нужен пакет python3-dbus и системный Python 3") from None
    try:
        bus = dbus.SystemBus()
        if not bus.name_has_owner("org.freedesktop.resolve1"):
            raise RuntimeError("systemd-resolved не запущен")
        return dbus, bus
    except dbus.DBusException:
        raise RuntimeError("Нет доступа к systemd-resolved через D-Bus") from None


def require_resolved():
    try:
        nameservers = [line.split()[1] for line in Path("/etc/resolv.conf").read_text().splitlines()
                       if len(line.split()) >= 2 and line.split()[0] == "nameserver"]
    except OSError:
        raise RuntimeError("Не удалось прочитать /etc/resolv.conf") from None
    if nameservers != ["127.0.0.53"]:
        raise RuntimeError("Для безопасного split DNS требуется systemd-resolved с DNS stub 127.0.0.53")
    _resolved_bus()


def configure_resolved_link(interface):
    dbus, bus = _resolved_bus()
    manager = None
    index = socket.if_nametoindex(interface)
    try:
        manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"),
                                 "org.freedesktop.resolve1.Manager")
        addresses = dbus.Array([(dbus.Int32(socket.AF_INET), dbus.ByteArray(b"\xc6\x12\x00\x02"))], signature="(iay)")
        domains = dbus.Array([(dbus.String("."), dbus.Boolean(True))], signature="(sb)")
        manager.SetLinkDNS(index, addresses)
        manager.SetLinkDomains(index, domains)
        manager.SetLinkDefaultRoute(index, True)
        manager.SetLinkLLMNR(index, "no")
        manager.SetLinkMulticastDNS(index, "no")
        manager.SetLinkDNSOverTLS(index, "no")
    except dbus.DBusException:
        if manager is not None:
            try:
                manager.RevertLink(index)
            except dbus.DBusException:
                pass
        raise RuntimeError("Не удалось настроить DNS туннеля через D-Bus") from None


def resolved_link_ready(interface):
    dbus, bus = _resolved_bus()
    try:
        manager = dbus.Interface(bus.get_object("org.freedesktop.resolve1", "/org/freedesktop/resolve1"),
                                 "org.freedesktop.resolve1.Manager")
        path = manager.GetLink(socket.if_nametoindex(interface))
        properties = dbus.Interface(bus.get_object("org.freedesktop.resolve1", path),
                                    "org.freedesktop.DBus.Properties")
        link = "org.freedesktop.resolve1.Link"
        servers = [(int(family), bytes(address)) for family, address in properties.Get(link, "DNS")]
        domains = [(str(domain), bool(routing)) for domain, routing in properties.Get(link, "Domains")]
        return servers == [(socket.AF_INET, b"\xc6\x12\x00\x02")] and (".", True) in domains and bool(properties.Get(link, "DefaultRoute"))
    except (dbus.DBusException, OSError):
        return False


def ipv6_enabled():
    try:
        disabled = Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "1"
        default_disabled = Path("/proc/sys/net/ipv6/conf/default/disable_ipv6").read_text().strip() == "1"
    except FileNotFoundError:
        return False
    if not disabled and default_disabled:
        raise RuntimeError("IPv6 включён, но отключён для новых интерфейсов; безопасный TUN невозможен")
    return not disabled


def detach_worker():
    reader, writer = os.pipe()
    try:
        child = os.fork()
    except BaseException:
        os.close(reader)
        os.close(writer)
        raise
    if child:
        os.close(writer)
        try:
            if os.read(reader, 1) != b"1":
                raise RuntimeError("Не удалось отделить управляющий процесс Xray")
        finally:
            os.close(reader)
        return False
    os.close(reader)
    try:
        os.setsid()
        os.write(writer, b"1")
    finally:
        os.close(writer)
    return True


def process_start_time(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rfind(")") + 2:].split()
        if fields[0] in ("Z", "X"):
            return None
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def process_owns_interface(pid, name):
    try:
        for info in Path(f"/proc/{pid}/fdinfo").iterdir():
            try:
                if any(line.split() == ["iff:", name] for line in info.read_text().splitlines()):
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False


def worker_matches(state):
    try:
        pid = int(state["pid"])
        start = int(state["start_time"])
        nonce = state["nonce"]
        if pid <= 1 or not isinstance(nonce, str) or len(nonce) != 32 or not all(c in "0123456789abcdef" for c in nonce):
            return False
        if Path(f"/proc/{pid}").stat().st_uid != 0 or process_start_time(pid) != start:
            return False
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        return b"_worker" in args and b"--nonce" in args and nonce.encode() in args
    except (OSError, ValueError, TypeError, KeyError):
        return False


def engine_matches(state, state_dir):
    try:
        pid = int(state["engine_pid"])
        start = int(state["engine_start_time"])
        core = os.fsencode(state["core"])
        config = os.fsencode(str(Path(state_dir) / "runtime.json"))
        if pid <= 1 or Path(f"/proc/{pid}").stat().st_uid != 0 or process_start_time(pid) != start:
            return False
        args = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        return args[0] == core and b"-config" in args and config in args
    except (OSError, ValueError, TypeError, KeyError):
        return False


def _named_processes(name):
    found = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            if (process / "comm").read_text().strip() == name and process_start_time(int(process.name)) is not None:
                found.append(int(process.name))
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.EACCES, errno.EPERM, errno.ESRCH):
                raise
    return found


def other_onexray_cores():
    return _named_processes("OneXrayCore")


def onexray_gui_running():
    return bool(_named_processes("OneXray"))
