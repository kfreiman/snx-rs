import ipaddress
import shutil
import subprocess
import time
from pathlib import Path

from dual_vpn.config import ConfigError
from dual_vpn.providers.base import Ctx
from dual_vpn.providers.snx_docker import AuthPendingError
from dual_vpn.providers import build_provider
from dual_vpn import state as state_mod


class Orchestrator:
    def __init__(self, dual_config, ctx=None):
        self.cfg = dual_config
        self.ctx = ctx or Ctx(state_mod.state_dir())
        self.providers = {}
        for name in dual_config.start_order:
            ref = dual_config.providers[name]
            self.providers[name] = build_provider(name, ref.type, ref.config)

    def build_bypasses(self, started, require_xray=False):
        bypasses = []
        for name in started:
            provider = self.providers[name]
            endpoints = provider.endpoints(self.ctx)
            if require_xray and provider.NAME == "xray" and not endpoints:
                raise RuntimeError("Не удалось определить адрес Xray для исключения из маршрутизации доменов")
            for endpoint in endpoints:
                net = ipaddress.IPv4Network(f"{endpoint}/32")
                if net not in bypasses:
                    bypasses.append(net)
        return bypasses

    def doctor(self):
        problems = []
        if shutil.which("python3") is None:
            problems.append("нет python3")
        for name, provider in self.providers.items():
            for problem in provider.check(self.ctx):
                problems.append(f"[{name}] {problem}")
        corp = self.providers.get("corp")
        if corp is not None and corp.NAME == "snx-docker" and "personal" in self.cfg.start_order:
            if corp.cfg.gateway_via == "default" and self.cfg.start_order.index("corp") < self.cfg.start_order.index("personal"):
                problems.append("порядок corp→personal при gateway_via=default: CCC пойдёт напрямую; нужен порядок personal→corp")
        routes_conflict = self._foreign_defaults()
        problems.extend(routes_conflict)
        return problems

    def _foreign_defaults(self):
        try:
            from xray_cli.platform import linux
            routes = linux.main_routes()
        except Exception:
            return []
        warnings = []
        for iface, network, gateway, metric in routes:
            if network.prefixlen == 0 and iface not in ("lo", "xraycli0", "docker0") and iface.startswith(("tailscale", "zt", "wg", "tun", "utun")):
                warnings.append(f"посторонний default через {iface}: порядок uplink может быть нарушен")
        return warnings

    def start(self, dry_run=False):
        with state_mod.global_lock(self.ctx.state_dir):
            problems = self.doctor()
            for problem in problems:
                print(f"doctor: {problem}")
            if problems and not dry_run:
                raise RuntimeError("Исправьте замечания doctor перед запуском")
            pre_running = set()
            if not dry_run:
                for name in self.cfg.start_order:
                    try:
                        if self.providers[name].status(self.ctx).running:
                            pre_running.add(name)
                    except Exception:
                        pass
            started = []
            current = None
            try:
                for name in self.cfg.start_order:
                    current = name
                    bypasses = self.build_bypasses(started)
                    provider = self.providers[name]
                    if name == "corp" and getattr(provider.cfg, "route_domains", []):
                        peers = [n for n in self.cfg.start_order if n != "corp"]
                        for network in self.build_bypasses(peers, require_xray=True):
                            if network not in bypasses:
                                bypasses.append(network)
                    print(f"==> start {name} (bypass: {', '.join(str(b) for b in bypasses) or 'нет'})")
                    if not dry_run:
                        self.providers[name].start(self.ctx, bypasses)
                    started.append(name)
                    current = None
                    if not dry_run:
                        self._probe(name)
                if not dry_run:
                    corp = self.providers.get("corp")
                    if (corp is not None and getattr(corp.cfg, "route_domains", [])
                            and self.cfg.start_order.index("corp") != len(self.cfg.start_order) - 1):
                        peers = [n for n in started if n != "corp"]
                        corp.configure_domain_routes(self.ctx, self.build_bypasses(peers, require_xray=True))
                    try:
                        self._probe_health()
                    except RuntimeError as exc:
                        print(f"WARN {exc}. Corp-туннель поднят; проверьте вручную curl {self.cfg.health.url}")
                self._write_state(started, "ready")
                return started
            except AuthPendingError:
                self._write_state(started, "auth-pending")
                raise
            except Exception:
                rollback = [n for n in started if n not in pre_running]
                if current is not None and current not in pre_running:
                    try:
                        self.providers[current].stop(self.ctx)
                    except Exception as exc:
                        print(f"WARN cleanup {current}: {exc}")
                for name in reversed(rollback):
                    try:
                        self.providers[name].stop(self.ctx)
                    except Exception as exc:
                        print(f"WARN rollback {name}: {exc}")
                self._write_state([], "rolled-back")
                raise

    def _probe(self, name):
        self.providers[name].probe(self.ctx)

    def _probe_health(self):
        health = self.cfg.health
        if not health.url:
            return
        proc = subprocess.run(["curl", "--silent", "--show-error", "--location", "--output", "/dev/null",
                              "--connect-timeout", str(health.timeout), "--max-time", str(health.timeout), health.url],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or "").strip()[-200:] if proc.stderr else ""
            raise RuntimeError(f"Health-проверка {health.url} не прошла ({detail or proc.returncode})")

    def stop(self):
        with state_mod.global_lock(self.ctx.state_dir):
            errors = []
            for name in reversed(self.cfg.start_order):
                try:
                    self.providers[name].stop(self.ctx)
                    print(f"==> stop {name}")
                except Exception as exc:
                    errors.append(f"{name}: {exc}")
            self._write_state([], "stopped")
            if errors:
                raise RuntimeError("; ".join(errors))

    def reload_domains(self):
        with state_mod.global_lock(self.ctx.state_dir):
            corp = self.providers.get("corp")
            if corp is None or corp.NAME != "snx-docker":
                raise RuntimeError("Для reload-domains нужен корпоративный провайдер snx-docker")
            peers = [name for name in self.providers if name != "corp"]
            corp.configure_domain_routes(self.ctx, self.build_bypasses(peers, require_xray=bool(corp.cfg.route_domains)))

    def status(self):
        rows = []
        for name in self.cfg.start_order:
            st = self.providers[name].status(self.ctx)
            rows.append((name, st.running, st.detail, st.interfaces))
        return rows

    def _reconnect(self, name, started):
        try:
            with state_mod.global_lock(self.ctx.state_dir):
                if state_mod.read_state(self.ctx.state_dir).get("phase") != "ready":
                    return False
                provider = self.providers[name]
                protect_xray = name == "corp" and bool(getattr(provider.cfg, "route_domains", []))
                bypasses = self.build_bypasses([n for n in started if n != name], require_xray=protect_xray)
                provider.stop(self.ctx)
                provider.start(self.ctx, bypasses)
                corp = self.providers.get("corp")
                if name != "corp" and corp is not None and getattr(corp.cfg, "route_domains", []):
                    peers = [n for n in started if n != "corp"]
                    corp.configure_domain_routes(self.ctx, self.build_bypasses(peers, require_xray=True))
            return True
        except state_mod.LockBusyError:
            print("WARN переподключение отложено: другая операция dual-vpn ещё выполняется")
            return True

    def monitor(self, interval=None):
        interval = interval or self.cfg.health.interval
        started = self.start()
        failures = {name: 0 for name in started}
        print(f"Мониторинг: каждые {interval}с, порог {self.cfg.health.failure_threshold}")
        try:
            while True:
                time.sleep(interval)
                if state_mod.read_state(self.ctx.state_dir).get("phase") != "ready":
                    print("Мониторинг остановлен: VPN отключён или перенастраивается.")
                    return
                try:
                    self._probe_health()
                    if "corp" in failures:
                        failures["corp"] = 0
                except Exception as exc:
                    if "corp" in failures:
                        failures["corp"] += 1
                        print(f"WARN probe corp: {exc} ({failures['corp']}/{self.cfg.health.failure_threshold})")
                        if failures["corp"] >= self.cfg.health.failure_threshold:
                            print("==> reconnect corp")
                            if not self._reconnect("corp", started):
                                return
                            failures["corp"] = 0
                for name in started:
                    try:
                        self._probe(name)
                        failures[name] = 0
                    except Exception as exc:
                        failures[name] += 1
                        print(f"WARN probe {name}: {exc} ({failures[name]}/{self.cfg.health.failure_threshold})")
                        if failures[name] >= self.cfg.health.failure_threshold:
                            print(f"==> reconnect {name}")
                            if not self._reconnect(name, started):
                                return
                            failures[name] = 0
        except KeyboardInterrupt:
            print("Прервано.")

    def _write_state(self, started, phase):
        state_mod.write_state(self.ctx.state_dir, {"order": started, "phase": phase, "time": time.time()})
