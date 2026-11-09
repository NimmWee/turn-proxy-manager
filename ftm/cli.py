"""Local read-only CLI. Error output deliberately excludes file contents."""

import argparse
import json
from pathlib import Path
import sys

from .installer import build_plan, inspect_state, read_private_json, validate_config
from .preflight import collect, evaluate


def wizard(input_fn=input, output_fn=print, has_state=False):
    output_fn("FreeTurn Manager — предварительный мастер (без установки)")
    modes = {"1": "fresh", "2": "migrate", "3": "repair"}
    default = "2" if has_state else "1"
    mode = modes.get(input_fn(f"Режим: 1 — новая установка, 2 — миграция, 3 — проверка [{default}]: ").strip() or default)
    if mode is None:
        raise ValueError("Неизвестный режим установки.")
    choice = input_fn("Адрес: 1 — свой домен, 2 — публичный IP [1]: ").strip() or "1"
    if choice not in {"1", "2"}:
        raise ValueError("Неизвестный вариант адреса.")
    web_mode = "domain" if choice == "1" else "ip"
    host = input_fn("Домен без https://: " if web_mode == "domain" else "Публичный IPv4: ").strip()
    if web_mode == "domain":
        access = input_fn("Панель: 1 — публичный HTTPS, 2 — только VPN/SSH [1]: ").strip() or "1"
    else:
        output_fn("Публичный IP требует доверенного IP-сертификата. По умолчанию доступ только VPN/SSH.")
        access = input_fn("Панель: 1 — публичный HTTPS с доверенным IP TLS, 2 — только VPN/SSH [2]: ").strip() or "2"
    if access not in {"1", "2"}:
        raise ValueError("Неизвестный вариант доступа.")
    private = access == "2"
    return validate_config({"schema_version": 1, "mode": mode, "web_mode": web_mode, "web_host": host,
                            "panel_access": "private" if private else "public",
                            "tls_mode": "private" if private else ("domain" if web_mode == "domain" else "ip-trusted")})


def main(argv=None):
    parser = argparse.ArgumentParser(description="FreeTurn Manager: локальная проверка и план установки")
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install", help="План установки; apply пока не реализован")
    install.add_argument("--manager", action="store_true", help="Совместимый необязательный флаг")
    install.add_argument("--dry-run", action="store_true", help="Только показать план, без изменений системы")
    install.add_argument("--non-interactive", action="store_true")
    install.add_argument("--config", type=Path, help="JSON-файл 0600; не исполняется как shell")
    install.add_argument("--state", type=Path, help="Состояние существующей Vps-установки")
    inspect = commands.add_parser("inspect", help="Проверить state Vps без раскрытия ключей")
    inspect.add_argument("--state", type=Path, required=True)
    commands.add_parser("preflight", help="Прочитать ОС, ресурсы и занятые порты без изменения хоста")
    security = commands.add_parser("secure-ssh", help="Настроить установленный Fail2ban: 3 ошибки → 365 дней")
    security.add_argument("--apply", action="store_true", help="Явно применить защиту SSH (root/Linux)")
    args = parser.parse_args(argv)
    try:
        if args.command == "secure-ssh":
            if not args.apply:
                raise ValueError("Для настройки Fail2ban нужен явный --apply; пакеты должны быть установлены.")
            from .ssh_protection import configure
            report = configure()
        elif args.command == "preflight":
            report = evaluate(collect())
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["preflight_ready"] else 2
        elif args.command == "inspect":
            report = inspect_state(read_private_json(args.state, 1048576))
        else:
            if not args.dry_run:
                print("Установка Manager ещё не реализована. Используйте --dry-run для проверки плана.", file=sys.stderr)
                return 3
            state_path = args.state or Path("/var/lib/vps-vk/main/state.json")
            state = read_private_json(state_path, 1048576) if args.state or state_path.exists() else None
            if args.config:
                # Keep explicit network fields distinguishable from inherited defaults.
                config = validate_config(read_private_json(args.config))
            elif args.non_interactive:
                raise ValueError("Для --non-interactive обязателен --config.")
            elif not sys.stdin.isatty():
                raise ValueError("Для мастера нужен терминал; для CI используйте --non-interactive --config.")
            else:
                config = wizard(has_state=state is not None)
            report = build_plan(config, state)
            if not args.config:
                print(json.dumps(report, ensure_ascii=False, indent=2))
                answer = input("Завершить просмотр плана? [Y/n]: ").strip().lower()
                if answer not in {"", "y", "yes", "д", "да"}:
                    print("Отменено. Изменений нет.", file=sys.stderr)
                    return 1
                return 0
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except (EOFError, KeyboardInterrupt):
        print("Отменено. Изменений нет.", file=sys.stderr)
        return 130
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 2
    except OSError:
        print("Ошибка доступа к файлу. Проверьте путь, владельца и права. Содержимое скрыто.", file=sys.stderr)
        return 2
    except RuntimeError:
        print("Не удалось применить защиту SSH. Выполнен откат конфигурации; проверьте службу Fail2ban.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
