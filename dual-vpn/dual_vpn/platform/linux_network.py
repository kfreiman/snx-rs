import ctypes
import errno
import ipaddress
import os
import socket
import struct


NLMSG_ERROR = 2
NLMSG_DONE = 3
RTM_NEWLINK = 16
RTM_DELLINK = 17
RTM_NEWADDR = 20
RTM_NEWROUTE = 24
RTM_DELROUTE = 25
RTM_GETROUTE = 26
RTM_NEWRULE = 32
RTM_DELRULE = 33
RTM_GETRULE = 34


def attribute(kind, value):
    data = struct.pack("=HH", len(value) + 4, kind) + value
    return data + b"\0" * (-len(data) % 4)


def attributes(data):
    offset = 0
    while offset + 4 <= len(data):
        size, kind = struct.unpack_from("=HH", data, offset)
        if size < 4 or offset + size > len(data):
            raise RuntimeError("Некорректный ответ netlink")
        yield kind & 0x3FFF, data[offset + 4:offset + size]
        offset += (size + 3) & ~3
    if offset != len(data):
        raise RuntimeError("Некорректный ответ netlink")


def u32(value):
    return struct.pack("=I", value)


def netlink(kind, payload, create=False, dump=False):
    flags = 1 | (0x300 if dump else 4) | (0x600 if create else 0)
    header = struct.pack("=IHHII", 16 + len(payload), kind, flags, 1, 0)
    replies = []
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as conn:
        conn.bind((0, 0))
        conn.settimeout(5)
        conn.send(header + payload)
        while True:
            data = conn.recv(1024 * 1024)
            offset = 0
            while offset + 16 <= len(data):
                size, msg_type, _, sequence, _ = struct.unpack_from("=IHHII", data, offset)
                if size < 16 or offset + size > len(data):
                    raise RuntimeError("Некорректный ответ netlink")
                body = data[offset + 16:offset + size]
                offset += (size + 3) & ~3
                if sequence != 1:
                    continue
                if msg_type == NLMSG_DONE:
                    return replies
                if msg_type == NLMSG_ERROR:
                    if len(body) < 4:
                        raise RuntimeError("Некорректная ошибка netlink")
                    error = struct.unpack_from("=i", body)[0]
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    if not dump:
                        return replies
                else:
                    replies.append((msg_type, body))
            if offset != len(data):
                raise RuntimeError("Некорректный ответ netlink")


def route_message(table, interface, gateway=None):
    result = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 4, 0, 1, 0)
    result += attribute(15, u32(table)) + attribute(4, u32(socket.if_nametoindex(interface)))
    if gateway:
        result += attribute(5, ipaddress.IPv4Address(gateway).packed)
    return result


def rule_message(table, priority, mark=None, mask=None, incoming=None):
    result = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 1, 0)
    result += attribute(15, u32(table)) + attribute(6, u32(priority))
    if mark is not None:
        result += attribute(10, u32(mark)) + attribute(16, u32(mask))
    if incoming:
        result += attribute(3, incoming.encode("ascii") + b"\0")
    return result


def add_route(table, interface, gateway=None):
    netlink(RTM_NEWROUTE, route_message(table, interface, gateway), create=True)


def delete_route(table, interface, gateway=None):
    try:
        netlink(RTM_DELROUTE, route_message(table, interface, gateway))
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ESRCH, errno.ENODEV, errno.ENXIO):
            raise


def add_rule(table, priority, mark=None, mask=None, incoming=None):
    netlink(RTM_NEWRULE, rule_message(table, priority, mark, mask, incoming), create=True)


def delete_rule(table, priority, mark=None, mask=None, incoming=None):
    try:
        netlink(RTM_DELRULE, rule_message(table, priority, mark, mask, incoming))
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ESRCH, errno.ENODEV, errno.ENXIO):
            raise


def _table(header, attrs):
    value = attrs.get(15)
    return struct.unpack("=I", value)[0] if value and len(value) == 4 else header[4]


def check_available(table, priorities):
    header = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0)
    for kind, body in netlink(RTM_GETROUTE, header, dump=True):
        if kind == RTM_NEWROUTE and len(body) >= 12:
            route = struct.unpack_from("=BBBBBBBBI", body)
            if route[0] == socket.AF_INET and _table(route, dict(attributes(body[12:]))) == table:
                raise RuntimeError(f"Таблица маршрутов {table} уже используется")
    for kind, body in netlink(RTM_GETRULE, header, dump=True):
        if kind != RTM_NEWRULE or len(body) < 12:
            continue
        rule = struct.unpack_from("=BBBBBBBBI", body)
        if rule[0] != socket.AF_INET:
            continue
        attrs = dict(attributes(body[12:]))
        priority = attrs.get(6)
        priority = struct.unpack("=I", priority)[0] if priority and len(priority) == 4 else None
        if priority in priorities or _table(rule, attrs) == table:
            raise RuntimeError(f"Правила маршрутизации {table}/{priority} уже используются")


def route_present(table, interface, gateway=None):
    expected = dict(attributes(route_message(table, interface, gateway)[12:]))
    header = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0)
    for kind, body in netlink(RTM_GETROUTE, header, dump=True):
        if kind != RTM_NEWROUTE or len(body) < 12:
            continue
        route = struct.unpack_from("=BBBBBBBBI", body)
        attrs = dict(attributes(body[12:]))
        if (route[0] == socket.AF_INET and route[1] == 0 and _table(route, attrs) == table
                and all(attrs.get(key) == value for key, value in expected.items())):
            return True
    return False


def rule_present(table, priority, mark=None, mask=None, incoming=None):
    expected = dict(attributes(rule_message(table, priority, mark, mask, incoming)[12:]))
    header = struct.pack("=BBBBBBBBI", socket.AF_INET, 0, 0, 0, 0, 0, 0, 0, 0)
    for kind, body in netlink(RTM_GETRULE, header, dump=True):
        if kind != RTM_NEWRULE or len(body) < 12:
            continue
        rule = struct.unpack_from("=BBBBBBBBI", body)
        attrs = dict(attributes(body[12:]))
        if (rule[0] == socket.AF_INET and _table(rule, attrs) == table
                and all(attrs.get(key) == value for key, value in expected.items())):
            return True
    return False


def link_message(index=0, flags=0, change=0):
    return struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, index, flags, change)


def add_dummy(name, address):
    try:
        socket.if_nametoindex(name)
    except OSError:
        pass
    else:
        raise RuntimeError(f"Интерфейс {name} уже существует")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.bind((str(address), 0))
        except OSError as exc:
            if exc.errno != errno.EADDRNOTAVAIL:
                raise
        else:
            raise RuntimeError(f"Адрес DNS {address} уже используется")
    info = attribute(18 | 0x8000, attribute(1, b"dummy\0"))
    netlink(RTM_NEWLINK, link_message() + attribute(3, name.encode("ascii") + b"\0") + info, create=True)
    index = socket.if_nametoindex(name)
    try:
        netlink(RTM_NEWLINK, link_message(index, 1, 1))
        packed = ipaddress.IPv4Address(address).packed
        msg = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 0, index)
        netlink(RTM_NEWADDR, msg + attribute(1, packed) + attribute(2, packed), create=True)
        return index
    except BaseException:
        delete_link(name)
        raise


def delete_link(name):
    try:
        index = socket.if_nametoindex(name)
    except OSError as exc:
        if exc.errno in (errno.ENODEV, errno.ENXIO):
            return
        raise
    try:
        netlink(RTM_DELLINK, link_message(index))
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ESRCH, errno.ENODEV):
            raise


class Nftables:
    def __init__(self):
        self.lib = ctypes.CDLL("libnftables.so.1")
        self.lib.nft_ctx_new.argtypes = [ctypes.c_uint32]
        self.lib.nft_ctx_new.restype = ctypes.c_void_p
        self.lib.nft_ctx_free.argtypes = [ctypes.c_void_p]
        self.lib.nft_ctx_buffer_output.argtypes = [ctypes.c_void_p]
        self.lib.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
        self.lib.nft_ctx_get_output_buffer.argtypes = [ctypes.c_void_p]
        self.lib.nft_ctx_get_output_buffer.restype = ctypes.c_char_p
        self.lib.nft_ctx_get_error_buffer.argtypes = [ctypes.c_void_p]
        self.lib.nft_ctx_get_error_buffer.restype = ctypes.c_char_p
        self.lib.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self.lib.nft_run_cmd_from_buffer.restype = ctypes.c_int

    def run(self, commands, check=True):
        context = self.lib.nft_ctx_new(0)
        if not context:
            raise RuntimeError("Не удалось создать контекст nftables")
        try:
            self.lib.nft_ctx_buffer_output(context)
            self.lib.nft_ctx_buffer_error(context)
            status = self.lib.nft_run_cmd_from_buffer(context, commands.encode("ascii"))
            output = (self.lib.nft_ctx_get_output_buffer(context) or b"").decode(errors="replace")
            error = (self.lib.nft_ctx_get_error_buffer(context) or b"").decode(errors="replace")
            if status and check:
                raise RuntimeError(f"Ошибка nftables: {error.strip() or status}")
            return status, output
        finally:
            self.lib.nft_ctx_free(context)

    def owned(self, table, token):
        status, output = self.run(f"list table ip {table}", check=False)
        return status == 0 and f'comment "dual-vpn:{token}"' in output
