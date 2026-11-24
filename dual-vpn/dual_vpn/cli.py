import argparse
import sys

from dual_vpn.config import ConfigError, load_dual_config
from dual_vpn.orchestrator import Orchestrator


def _parser():
    result = argparse.ArgumentParser(prog="dual-vpn", description="Xray + Check Point одновременно (Linux)")
    result.add_argument("--config", default=None, help="путь к dual-vpn.yaml")
    commands = result.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start", help="поднять провайдеры по порядку")
    start.add_argument("--dry-run", action="store_true", help="проверить конфиг и план без изменений")
    start.add_argument("--monitor", action="store_true", help="мониторинг в foreground с автопереподключением")
    commands.add_parser("stop", help="остановить в обратном порядке")
    commands.add_parser("restart", help="stop + start")
    commands.add_parser("reload-domains", help="применить route_domains без перезапуска VPN")
    commands.add_parser("status", help="состояние провайдеров")
    commands.add_parser("doctor", help="preflight-проверки")
    logs = commands.add_parser("logs", help="логи провайдера")
    logs.add_argument("--provider", required=True)
    logs.add_argument("--lines", type=int, default=50)
    return result


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        dual = load_dual_config(args.config)
        orch = Orchestrator(dual)
        if args.command == "doctor":
            problems = orch.doctor()
            for problem in problems:
                print(f"doctor: {problem}")
            if problems:
                print(f"Итого замечаний: {len(problems)}")
                return 1
            print("doctor: OK (замечаний нет)")
            return 0
        if args.command == "reload-domains":
            orch.reload_domains()
            print("Настройки маршрутизации доменов применены без перезапуска VPN.")
            return 0
        if args.command == "status":
            for name, running, detail, ifaces in orch.status():
                mark = "running" if running else "stopped"
                print(f"{name}: {mark} ({detail}) [{', '.join(ifaces) or '—'}]")
            return 0
        if args.command == "start":
            if args.monitor:
                orch.monitor()
            else:
                for name in orch.start(dry_run=args.dry_run):
                    print(f"{name}: {'dry-run (без изменений)' if args.dry_run else 'started'}")
            return 0
        if args.command == "stop":
            orch.stop()
            print("dual-vpn остановлен.")
            return 0
        if args.command == "restart":
            orch.stop()
            for name in orch.start():
                print(f"{name}: started")
            return 0
        if args.command == "logs":
            if args.provider not in orch.providers:
                print(f"Ошибка: неизвестный провайдер {args.provider}", file=sys.stderr)
                return 1
            provider = orch.providers[args.provider]
            if provider.NAME == "snx-docker":
                import subprocess
                from pathlib import Path
                log_path = Path(orch.ctx.state_dir) / "corp" / "snx-rs-container.log"
                if log_path.is_file():
                    for line in log_path.read_text(errors="replace").splitlines()[-args.lines:]:
                        print(line)
                else:
                    proc = subprocess.run(["docker", "logs", "--tail", str(args.lines), provider.cfg.container_name],
                                          capture_output=True, text=True)
                    print(proc.stdout or proc.stderr)
                return 0
            from dual_vpn.providers.xray import _import_xray
            cli = _import_xray()
            try:
                cli.logs(type("A", (), {"lines": args.lines}))
            except RuntimeError as exc:
                print(f"Ошибка: {exc}", file=sys.stderr)
                return 1
            return 0
        return 2
    except ConfigError as exc:
        print(f"Ошибка конфига: {exc}", file=sys.stderr)
        return 1
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
