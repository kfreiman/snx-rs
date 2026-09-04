#!/usr/bin/env python3
"""Private helper for run_amneziawg_vpn.sh.

It imports the Qt/QSettings profile format used by AmneziaVPN and talks to the
userspace AmneziaWG daemon over its UAPI socket. It never prints private keys.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import sys
import time
from pathlib import Path


def decode_qsettings(raw: str) -> str:
    result: list[str] = []
    pos = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t"}
    while pos < len(raw):
        if raw[pos] != "\\" or pos + 1 >= len(raw):
            result.append(raw[pos])
            pos += 1
            continue
        code = raw[pos + 1]
        if code == "x" and pos + 3 < len(raw):
            result.append(chr(int(raw[pos + 2 : pos + 4], 16)))
            pos += 4
        else:
            result.append(escapes.get(code, code))
            pos += 2
    return "".join(result)


def read_servers(path: str) -> tuple[str, list[dict], int]:
    source = Path(path).read_text(encoding="utf-8")
    match = re.search(r'^serversList="@ByteArray\((.*)\)"\s*$', source, re.MULTILINE)
    if not match:
        raise ValueError("serversList в формате AmneziaVPN не найден")
    try:
        servers = json.loads(decode_qsettings(match.group(1)))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Не удалось разобрать serversList: {exc}") from exc
    default = re.search(r"^defaultServerIndex=(\d+)\s*$", source, re.MULTILINE)
    return source, servers, int(default.group(1)) if default else 0


def server_name(server: dict, index: int) -> str:
    return str(server.get("description") or server.get("name") or f"profile-{index}")


def select_server(source: str, servers: list[dict], default: int, index: str, name: str) -> tuple[int, dict]:
    if index:
        try:
            selected = int(index)
        except ValueError as exc:
            raise ValueError("Индекс профиля должен быть числом") from exc
    elif name:
        matches = [i for i, server in enumerate(servers) if server_name(server, i) == name]
        if len(matches) != 1:
            raise ValueError(f"Профиль с названием {name!r} не найден однозначно")
        selected = matches[0]
    else:
        selected = default
    if selected < 0 or selected >= len(servers):
        raise ValueError(f"Индекс профиля вне диапазона: {selected}")
    return selected, servers[selected]


def section_values(config: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    section = ""
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            sections.setdefault(section, {})
        elif section and "=" in line:
            key, value = line.split("=", 1)
            sections[section][key.strip().lower()] = value.strip()
    return sections


def get_awg(server: dict, container_selector: str) -> tuple[dict, str]:
    container_name = container_selector or server.get("defaultContainer")
    for container in server.get("containers", []):
        if "awg" in container and (not container_name or container.get("container") == container_name):
            return container["awg"], str(container.get("container") or container_name or "")
    raise ValueError("AWG-контейнер для выбранного профиля не найден")


def build_config(source: str, server: dict, awg: dict) -> tuple[str, dict]:
    metadata: dict = {}
    last_config = awg.get("last_config")
    if last_config:
        try:
            metadata = json.loads(last_config)
        except json.JSONDecodeError:
            pass
    config = metadata.get("config")
    if not config:
        metadata = awg
        client_ip = metadata.get("client_ip")
        private_key = metadata.get("client_priv_key")
        server_key = metadata.get("server_pub_key")
        endpoint = f"{metadata.get('hostName') or server.get('hostName')}:{metadata.get('port') or server.get('port')}"
        if not all((client_ip, private_key, server_key, endpoint)):
            raise ValueError("В выбранном профиле отсутствует готовая AWG-конфигурация")
        lines = ["[Interface]", f"Address = {client_ip}", f"PrivateKey = {private_key}"]
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"):
            if metadata.get(key) not in (None, ""):
                lines.append(f"{key} = {metadata[key]}")
        lines.extend(["", "[Peer]", f"PublicKey = {server_key}"])
        if metadata.get("psk_key"):
            lines.append(f"PresharedKey = {metadata['psk_key']}")
        allowed = metadata.get("allowed_ips") or ["0.0.0.0/0"]
        lines.extend([
            f"AllowedIPs = {', '.join(allowed)}",
            f"Endpoint = {endpoint}",
            f"PersistentKeepalive = {metadata.get('persistent_keep_alive') or 25}",
        ])
        config = "\n".join(lines)

    primary = re.search(r"^primaryDns=([^\s]+)\s*$", source, re.MULTILINE)
    secondary = re.search(r"^secondaryDns=([^\s]+)\s*$", source, re.MULTILINE)
    config = config.replace("$PRIMARY_DNS", primary.group(1) if primary else "")
    config = config.replace("$SECONDARY_DNS", secondary.group(1) if secondary else "")
    config = config.strip() + "\n"
    values = section_values(config)
    if not values.get("interface") or not values.get("peer"):
        raise ValueError("В выбранном профиле нет секций Interface и Peer")

    peer = values["peer"]
    endpoint = peer.get("endpoint") or f"{metadata.get('hostName') or server.get('hostName')}:{metadata.get('port') or server.get('port')}"
    meta = {
        "endpoint": endpoint,
        "address": values["interface"].get("address", ""),
        "dns": values["interface"].get("dns", ""),
        "mtu": str(metadata.get("mtu") or awg.get("mtu") or ""),
        "allowed": peer.get("allowedips", ""),
    }
    return config, meta


def extract(argv: list[str]) -> None:
    source_path, config_path, meta_path, index, name, container = argv
    source, servers, default = read_servers(source_path)
    selected, server = select_server(source, servers, default, index, name)
    awg, container_name = get_awg(server, container)
    config, meta = build_config(source, server, awg)
    Path(config_path).write_text(config, encoding="utf-8")
    Path(config_path).chmod(0o600)
    fields = [str(selected), server_name(server, selected), meta["endpoint"], meta["address"], meta["dns"], meta["mtu"], container_name, meta["allowed"]]
    Path(meta_path).write_text("\t".join(fields) + "\n", encoding="utf-8")
    Path(meta_path).chmod(0o600)


def profiles(path: str) -> None:
    source, servers, default = read_servers(path)
    for index, server in enumerate(servers):
        marker = "*" if index == default else " "
        print(f"{marker} {index}: {server_name(server, index)} ({server.get('hostName', '')})")


def parse_key(value: str) -> str:
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Некорректный ключ в конфигурации") from exc
    if len(decoded) != 32:
        raise ValueError("Ключ в конфигурации имеет неправильную длину")
    return decoded.hex()


def uapi_request(path: str, payload: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(path)
        connection.sendall(payload)
        response = b""
        while b"\n\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors="replace")


def configure(socket_path: str, config_path: str, firewall_mark: str) -> None:
    values = section_values(Path(config_path).read_text(encoding="utf-8"))
    interface = values.get("interface", {})
    peer = values.get("peer", {})
    if not all((interface.get("privatekey"), peer.get("publickey"), peer.get("endpoint"))):
        raise ValueError("В конфигурации отсутствует PrivateKey, PublicKey или Endpoint")

    lines = ["set=1", "replace_peers=true", f"private_key={parse_key(interface['privatekey'])}", f"fwmark={firewall_mark}"]
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts"):
        if interface.get(key):
            mapping = {
                "headerprotectionkey": "header_protection_key",
                "contentpaddingaddition": "content_padding_addition",
                "rekeyaftertime": "rekey_after_time",
                "rekeytimeout": "rekey_timeout",
                "rejectaftertime": "reject_after_time",
                "keepalivetimeout": "keepalive_timeout",
                "maxhandshakeattempts": "max_handshake_attempts",
            }
            lines.append(f"{mapping.get(key, key)}={interface[key]}")
    lines.extend([f"public_key={parse_key(peer['publickey'])}", "replace_allowed_ips=true"])
    if peer.get("presharedkey"):
        lines.append(f"preshared_key={parse_key(peer['presharedkey'])}")
    lines.append(f"endpoint={peer['endpoint']}")
    if peer.get("persistentkeepalive"):
        lines.append(f"persistent_keepalive_interval={peer['persistentkeepalive']}")
    for allowed in peer.get("allowedips", "").split(","):
        allowed = allowed.strip()
        if allowed:
            lines.append(f"allowed_ip={allowed}")
    lines.extend(["protocol_version=1", ""])
    response = uapi_request(socket_path, ("\n".join(lines) + "\n").encode())
    errno = next((int(line.split("=", 1)[1]) for line in response.splitlines() if line.startswith("errno=")), 1)
    if errno:
        raise ValueError(f"UAPI отклонил конфигурацию (errno={errno})")


def status(socket_path: str) -> None:
    response = uapi_request(socket_path, b"get=1\n\n")
    peers: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in response.splitlines():
        key, _, value = line.partition("=")
        if key == "public_key":
            if current:
                peers.append(current)
            current = {}
        elif key in {"last_handshake_time_sec", "rx_bytes", "tx_bytes", "endpoint", "persistent_keepalive_interval", "errno"}:
            current[key] = value
    if current:
        peers.append(current)
    for number, peer in enumerate(peers, 1):
        handshake = int(peer.get("last_handshake_time_sec", "0"))
        age = "never" if not handshake else f"{max(0, int(time.time()) - handshake)}s ago"
        print(f"peer[{number}]: endpoint={peer.get('endpoint', 'unknown')} handshake={age} rx={peer.get('rx_bytes', '0')} tx={peer.get('tx_bytes', '0')}")


def main() -> None:
    command = sys.argv[1]
    try:
        if command == "extract":
            extract(sys.argv[2:])
        elif command == "profiles":
            profiles(sys.argv[2])
        elif command == "configure":
            configure(sys.argv[2], sys.argv[3], sys.argv[4])
        elif command == "status":
            status(sys.argv[2])
        else:
            raise ValueError(f"Неизвестная команда helper: {command}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
