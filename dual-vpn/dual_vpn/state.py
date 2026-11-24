import contextlib
import fcntl
import os
import stat
from pathlib import Path


class LockBusyError(RuntimeError):
    pass


def state_dir():
    value = os.environ.get("XDG_STATE_HOME", "")
    base = Path(value) if value and Path(value).is_absolute() else Path.home() / ".local/state"
    return base / "dual-vpn"


def private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError(f"Небезопасный каталог: {path}")
    os.chmod(path, 0o700)


@contextlib.contextmanager
def global_lock(directory):
    private_directory(directory)
    fd = os.open(directory / "lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError:
        raise LockBusyError("Другой dual-vpn уже выполняет операцию") from None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _atomic_json(path, value):
    import json
    import tempfile

    data = json.dumps(value, ensure_ascii=False, indent=2).encode() + b"\n"
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
    try:
        if os.geteuid() == 0:
            meta = path.parent.stat()
            os.fchown(fd, meta.st_uid, meta.st_gid)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            fd = -1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if fd != -1:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def write_state(directory, value):
    private_directory(directory)
    _atomic_json(Path(directory) / "state.json", value)


def read_state(directory):
    import json

    try:
        value = json.loads((Path(directory) / "state.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
