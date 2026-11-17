import argparse
import contextlib
import fcntl
import getpass
import http.client
import ipaddress
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path

from .config import Profile, ProfileError, build_xray_config, parse_vless


INTERFACE = "xraycli0"
LAUNCHER = Path(__file__).resolve().parent.parent / "xray-vpn"


def _linux():
    if sys.platform != "linux":
        raise RuntimeError("Этот CLI поддерживает только Linux")
    from .platform import linux
    return linux


def _xdg(name, fallback):
    value = os.environ.get(name, "")
    return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback


def config_dir():
    return _xdg("XDG_CONFIG_HOME", ".config") / "xray-vpn"


def state_dir():
    return _xdg("XDG_STATE_HOME", ".local/state") / "xray-vpn"


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError(f"Небезопасный каталог: {path}")
    os.chmod(path, 0o700)


def atomic_json(path, value):
    data = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
    fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        metadata = path.parent.stat()
        if os.geteuid() == 0:
            os.fchown(fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if fd != -1:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def read_json(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as source:
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("Слишком большой файл состояния")
    return json.loads(data)


@contextlib.contextmanager
def state_lock(directory):
    private_directory(directory)
    fd = os.open(directory / "lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_state(directory):
    try:
        value = read_json(directory / "worker.json")
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, OSError, ValueError):
        return {}


def load_profile():
    try:
        return Profile.from_dict(read_json(config_dir() / "profile.json"))
    except FileNotFoundError:
        raise RuntimeError("Нет профиля; сначала выполните ./xray-vpn import") from None
    except (json.JSONDecodeError, OSError):
        raise RuntimeError("Не удалось прочитать профиль Xray") from None


def import_profile(args):
    if args.file:
        with open(args.file, encoding="utf-8") as source:
            uri = source.read(16385)
    elif args.stdin or not sys.stdin.isatty():
        uri = sys.stdin.readline(16385)
    else:
        uri = getpass.getpass("Вставьте ссылку VLESS (ввод не отображается): ")
    profile = parse_vless(uri.rstrip("\r\n"))
    directory = config_dir()
    private_directory(directory)
    atomic_json(directory / "profile.json", asdict(profile))
    print(f"Профиль сохранён: {directory / 'profile.json'}")
    print(f"Сервер: {profile.host}:{profile.port}")


def find_core(value):
    candidate = value or os.environ.get("XRAY_CORE")
    if not candidate:
        candidate = "/opt/OneXray/OneXrayCore" if os.access("/opt/OneXray/OneXrayCore", os.X_OK) else shutil.which("OneXrayCore")
    if not candidate:
        raise RuntimeError("Не найден OneXrayCore; установите OneXray или укажите --core PATH")
    path = Path(candidate).expanduser().resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"OneXrayCore не является исполняемым файлом: {path}")
    return str(path)


def _sudo_validate():
    if os.geteuid() == 0:
        return
    if not shutil.which("sudo"):
        raise RuntimeError("Для управления TUN требуется sudo")
    if subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0:
        return
    if subprocess.run(["sudo", "-v"], check=False).returncode != 0:
        raise RuntimeError("Не удалось получить права sudo")


def _root_command(*args):
    command = [sys.executable, str(LAUNCHER), *args]
    return command if os.geteuid() == 0 else ["sudo", "-n", *command]


def _resolve_server(host, port):
    try:
        addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise RuntimeError("Не удалось разрешить IPv4-адрес сервера Xray") from None
    if not addresses:
        raise RuntimeError("У сервера Xray нет доступного IPv4-адреса")
    return str(ipaddress.IPv4Address(addresses[0][4][0]))


def _probe(linux):
    hostname = "api.ipify.org"
    try:
        answers = socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        raise RuntimeError("Не работает DNS через Xray; проверка подключения не выполнена") from None
    addresses = list(dict.fromkeys(item[4][0] for item in answers))[:3]
    context = ssl.create_default_context()
    for address in addresses:
        try:
            if linux.route_interface(address) != INTERFACE:
                continue
            connection = http.client.HTTPSConnection(hostname, timeout=12, context=context)
            try:
                raw = socket.create_connection((address, 443), timeout=12)
                try:
                    connection.sock = context.wrap_socket(raw, server_hostname=hostname)
                except BaseException:
                    raw.close()
                    raise
                connection.request("GET", "/", headers={"Host": hostname, "Connection": "close"})
                response = connection.getresponse()
                result = response.read(128).decode("ascii").strip()
                if response.status == 200 and isinstance(ipaddress.ip_address(result), ipaddress.IPv4Address):
                    return result
            finally:
                connection.close()
        except (OSError, ValueError, http.client.HTTPException, RuntimeError):
            continue
    raise RuntimeError("Проверка HTTPS через Xray не удалась; соединение отменено")


def _wait_ready(directory, nonce, sudo_process, protected_routes, ipv6):
    linux = _linux()
    deadline = time.monotonic() + 20
    route_error = None
    while time.monotonic() < deadline:
        state = read_state(directory)
        if state.get("nonce") == nonce:
            if not linux.worker_matches(state):
                break
            if linux.engine_matches(state, directory) and linux.interface_exists(INTERFACE) and linux.resolved_link_ready(INTERFACE):
                try:
                    if any(linux.route_interface(address) != original for address, original in protected_routes.items()):
                        route_error = "Изменился маршрут до шлюза Check Point или сервера Xray"
                    elif not any(linux.route_interface(address) == INTERFACE for address in ("1.1.1.1", "8.8.8.8", "9.9.9.9")):
                        route_error = "Другой VPN перехватывает IPv4-маршрут до Xray"
                    elif ipv6 and linux.route_interface("2606:4700:4700::1111") != INTERFACE:
                        route_error = "Другой маршрут перехватывает IPv6-трафик до Xray"
                    else:
                        return state
                except OSError:
                    route_error = "Не удалось проверить маршруты Xray"
        elif sudo_process.poll() not in (None, 0):
            break
        time.sleep(0.2)
    if route_error:
        raise RuntimeError(route_error)
    raise RuntimeError(f"Xray не запустился или не настроил DNS; подробности: {directory / 'xray.log'}")


def _stop_locked(directory, state, authenticate=True):
    linux = _linux()
    worker = linux.worker_matches(state)
    engine = linux.engine_matches(state, directory)
    if not worker and not engine:
        if linux.interface_exists(INTERFACE):
            raise RuntimeError(f"Интерфейс {INTERFACE} существует, но его владелец неизвестен; ничего не удалено")
        for name in ("worker.json", "runtime.json"):
            with contextlib.suppress(FileNotFoundError):
                (directory / name).unlink()
        return False
    if authenticate:
        _sudo_validate()
    result = subprocess.run(_root_command("_stop-worker", "--state-dir", str(directory), "--nonce", state.get("nonce", "")), check=False)
    if result.returncode != 0:
        raise RuntimeError("Не удалось остановить управляемый процесс Xray")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if not linux.worker_matches(state) and not linux.engine_matches(state, directory):
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Xray не завершился; проверьте состояние и лог")
    if linux.interface_exists(INTERFACE):
        raise RuntimeError(f"Xray завершился, но интерфейс {INTERFACE} ещё существует")
    for name in ("worker.json", "runtime.json"):
        with contextlib.suppress(FileNotFoundError):
            (directory / name).unlink()
    return True


def start(args):
    linux = _linux()
    directory = state_dir()
    with state_lock(directory):
        previous = read_state(directory)
        if linux.worker_matches(previous) and linux.engine_matches(previous, directory):
            print("Xray уже запущен.")
            return
        if linux.worker_matches(previous) or linux.engine_matches(previous, directory):
            raise RuntimeError("Найден незавершённый процесс Xray; сначала выполните ./xray-vpn stop")
        if linux.interface_exists(INTERFACE):
            raise RuntimeError(f"Интерфейс {INTERFACE} уже существует; чужая сеть не изменена")
        if linux.other_onexray_cores():
            raise RuntimeError("OneXray уже подключён; отключите GUI-клиент перед запуском CLI")
        if linux.onexray_gui_running():
            print("Предупреждение: закройте OneXray GUI до запуска CLI, чтобы он не управлял тем же Core.", file=sys.stderr)
        linux.require_resolved()
        profile = load_profile()
        core = find_core(args.core)
        ipv6 = linux.ipv6_enabled()
        server_ip = _resolve_server(profile.host, profile.port)
        routes = linux.main_routes()
        linux.validate_tun_networks(routes, ipv6)
        uplink = linux.physical_interface(routes, INTERFACE)
        checkpoints = linux.checkpoint_gateways()
        tun_network = ipaddress.IPv4Network("198.18.0.0/30")
        if any(ipaddress.IPv4Address(address) in tun_network for address in [*checkpoints, server_ip]):
            raise RuntimeError("Адрес VPN-сервера конфликтует с подсетью TUN")
        if linux.route_interface("198.18.0.2") != uplink:
            raise RuntimeError("Адрес DNS туннеля перехватывается другим VPN-маршрутом")
        exclusions = [str(network) for _, network, _, _ in routes if network.prefixlen]
        exclusions.extend(f"{address}/32" for address in checkpoints)
        for value in args.bypass:
            try:
                network = ipaddress.IPv4Network(value, strict=False)
            except ValueError:
                raise RuntimeError("Исключение --bypass должно быть IPv4-адресом или сетью CIDR") from None
            if network.overlaps(tun_network):
                raise RuntimeError("Исключение --bypass пересекается с подсетью TUN")
            exclusions.append(str(network))
        protected = {str(address): linux.route_interface(address) for address in [*checkpoints, server_ip]}
        runtime = build_xray_config(profile, server_ip, exclusions, INTERFACE, ipv6)
        nonce = secrets.token_hex(16)
        sudo_process = None
        started = False
        log_fd = None
        try:
            atomic_json(directory / "runtime.json", runtime)
            log_fd = os.open(directory / "xray.log", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.fchmod(log_fd, 0o600)
            _sudo_validate()
            command = _root_command("_worker", "--state-dir", str(directory), "--nonce", nonce, "--core", core, "--uplink", uplink)
            sudo_process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd)
            started = True
            state = _wait_ready(directory, nonce, sudo_process, protected, ipv6)
            if args.skip_probe:
                print(f"Xray запущен на {INTERFACE}; доступ к серверу не проверен (--skip-probe).")
            else:
                address = _probe(linux)
                if not linux.worker_matches(state) or not linux.engine_matches(state, directory):
                    raise RuntimeError("Процесс Xray завершился во время проверки")
                print(f"Xray подключён: {profile.host}:{profile.port}")
                print(f"Внешний IPv4 через Xray: {address}")
            if checkpoints:
                print("Шлюз Check Point оставлен вне Xray: " + ", ".join(map(str, checkpoints)))
        except BaseException:
            if started:
                state = read_state(directory)
                if state.get("nonce") == nonce:
                    try:
                        _stop_locked(directory, state, authenticate=False)
                    except Exception as error:
                        print(f"Не удалось автоматически остановить Xray: {error}", file=sys.stderr)
                elif sudo_process is not None and sudo_process.poll() is None:
                    sudo_process.terminate()
            with contextlib.suppress(FileNotFoundError):
                (directory / "runtime.json").unlink()
            raise
        finally:
            if log_fd is not None:
                os.close(log_fd)


def stop(_args):
    directory = state_dir()
    with state_lock(directory):
        if _stop_locked(directory, read_state(directory)):
            print("Xray остановлен; маршруты и DNS восстановлены.")
        else:
            print("Xray не запущен.")


def status(_args):
    linux = _linux()
    directory = state_dir()
    with state_lock(directory):
        state = read_state(directory)
        if linux.worker_matches(state) and linux.engine_matches(state, directory) and linux.interface_exists(INTERFACE):
            if not linux.resolved_link_ready(INTERFACE):
                print("Xray работает, но DNS туннеля не готов.")
                return 1
            print(f"Xray запущен: {INTERFACE}, PID {state['engine_pid']}.")
            return 0
        if linux.engine_matches(state, directory):
            print("Найден Xray без управляющего процесса; выполните ./xray-vpn stop.")
        else:
            print("Xray не запущен.")
        return 1


def logs(args):
    path = state_dir() / "xray.log"
    try:
        with open(path, encoding="utf-8", errors="replace") as log:
            for line in deque(log, maxlen=args.lines):
                print(line, end="")
    except FileNotFoundError:
        raise RuntimeError(f"Лог пока не создан: {path}") from None


def worker(args):
    linux = _linux()
    if os.geteuid() != 0:
        raise RuntimeError("Для внутреннего процесса нужны права root")
    if not linux.detach_worker():
        return
    directory = Path(args.state_dir)
    state_path = directory / "worker.json"
    runtime_path = directory / "runtime.json"
    state = {"pid": os.getpid(), "start_time": linux.process_start_time(os.getpid()), "nonce": args.nonce, "core": args.core}
    child = None
    stopping = False

    def request_stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        atomic_json(state_path, state)
        if stopping:
            return
        child = subprocess.Popen([args.core, "run", "-dns", "1.1.1.1:53", "-interface", args.uplink, "-config", str(runtime_path)])
        state["engine_pid"] = child.pid
        state["engine_start_time"] = linux.process_start_time(child.pid)
        atomic_json(state_path, state)
        deadline = time.monotonic() + 12
        dns_ready = False
        while child.poll() is None and not stopping and time.monotonic() < deadline:
            if linux.process_owns_interface(child.pid, INTERFACE):
                try:
                    linux.configure_resolved_link(INTERFACE)
                    dns_ready = True
                    break
                except (OSError, RuntimeError):
                    pass
            time.sleep(0.1)
        if not dns_ready and child.poll() is None and not stopping:
            raise RuntimeError("Не удалось настроить DNS или дождаться TUN-интерфейса")
        while child.poll() is None:
            if stopping:
                child.terminate()
                try:
                    child.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                break
            time.sleep(0.2)
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                child.wait(timeout=8)
            if child.poll() is None:
                child.kill()
                child.wait()
        if read_state(directory).get("nonce") == args.nonce:
            with contextlib.suppress(FileNotFoundError):
                runtime_path.unlink()


def stop_worker(args):
    linux = _linux()
    if os.geteuid() != 0:
        raise RuntimeError("Для остановки процесса нужны права root")
    directory = Path(args.state_dir)
    state = read_state(directory)
    if state.get("nonce") != args.nonce:
        return
    if linux.worker_matches(state):
        os.kill(int(state["pid"]), signal.SIGTERM)
    elif linux.engine_matches(state, directory):
        os.kill(int(state["engine_pid"]), signal.SIGTERM)


def _private_command(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--nonce", required=True)
    if argv[0] == "_worker":
        parser.add_argument("--core", required=True)
        parser.add_argument("--uplink", required=True)
    args = parser.parse_args(argv[1:])
    if argv[0] == "_worker":
        worker(args)
    else:
        stop_worker(args)


def parser():
    result = argparse.ArgumentParser(prog="xray-vpn", description="VLESS TCP/REALITY через установленный OneXrayCore (Linux)")
    commands = result.add_subparsers(dest="command", required=True)
    import_cmd = commands.add_parser("import", help="сохранить экспорт OneXray без вывода секрета")
    source = import_cmd.add_mutually_exclusive_group()
    source.add_argument("--file", metavar="PATH", help="прочитать VLESS-ссылку из файла")
    source.add_argument("--stdin", action="store_true", help="прочитать VLESS-ссылку из stdin")
    for name in ("start", "restart"):
        command = commands.add_parser(name, help="подключить Xray" if name == "start" else "перезапустить Xray")
        command.add_argument("--core", metavar="PATH", help="путь к исполняемому OneXrayCore")
        command.add_argument("--bypass", action="append", default=[], metavar="IP/CIDR", help="IPv4-адрес или сеть в обход Xray; можно повторить")
        command.add_argument("--skip-probe", action="store_true", help="не проверять HTTPS через api.ipify.org")
    commands.add_parser("stop", help="отключить Xray")
    commands.add_parser("status", help="проверить состояние")
    log_cmd = commands.add_parser("logs", help="показать журнал ошибок")
    log_cmd.add_argument("--lines", type=int, default=50, metavar="N")
    return result


def main(argv=None):
    os.umask(0o077)
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv and argv[0] in ("_worker", "_stop-worker"):
            _private_command(argv)
            return 0
        args = parser().parse_args(argv)
        if args.command == "import":
            import_profile(args)
        elif args.command == "start":
            start(args)
        elif args.command == "stop":
            stop(args)
        elif args.command == "restart":
            stop(args)
            start(args)
        elif args.command == "status":
            return status(args)
        elif args.command == "logs":
            if args.lines < 1 or args.lines > 10000:
                raise RuntimeError("Число строк должно быть от 1 до 10000")
            logs(args)
        return 0
    except (ProfileError, RuntimeError, OSError, ValueError) as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        return 130
