"""Read-only installation planning. Applying system changes is intentionally unavailable."""

import copy
import ipaddress
import json
import os
from pathlib import Path
import stat

from .legacy import baseline_module, validate_legacy_state

DEFAULTS = {"vpn_port": 56001, "backend_port": 51830, "subnet": "10.77.43.0/24"}
REQUIRED = {"schema_version", "mode", "web_mode", "web_host", "panel_access", "tls_mode"}


def read_private_json(path, limit=65536):
    """Bound reads and reject symlinks, special files and non-private POSIX files."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Символические ссылки не разрешены.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Нужен обычный файл допустимого размера.")
        if os.name == "posix":
            if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid not in {0, os.geteuid()}:
                raise ValueError("Файл должен принадлежать текущему пользователю или root и иметь режим 0600.")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Файл превышает допустимый размер.")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("Некорректный JSON; содержимое файла скрыто.") from None


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Повторяющееся поле JSON.")
        result[name] = value
    return result


def load_config(path):
    return validate_config(read_private_json(path))


def validate_config(value):
    if not isinstance(value, dict) or not REQUIRED <= value.keys() or value.keys() - REQUIRED - DEFAULTS.keys():
        raise ValueError("Неизвестные или отсутствующие поля конфигурации.")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Неподдерживаемая версия конфигурации.")
    for field, options in {"mode": ("fresh", "migrate", "repair"), "web_mode": ("domain", "ip"),
                           "panel_access": ("public", "private"),
                           "tls_mode": ("domain", "ip-trusted", "private")}.items():
        if not isinstance(value[field], str) or value[field] not in options:
            raise ValueError("Недопустимый режим конфигурации.")
    normalized = copy.deepcopy(value)
    try:
        host = baseline_module().validate_endpoint(value["web_host"])
        address = ipaddress.ip_address(host) if value["web_mode"] == "ip" else None
    except (ValueError, TypeError):
        raise ValueError("Укажите корректный домен или публичный IPv4 без URL и порта.") from None
    if value["web_mode"] == "domain":
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("Для доменного режима нужно DNS-имя.")
    elif address.version != 4 or not address.is_global:
        raise ValueError("Для режима IP нужен публичный IPv4.")
    if value["panel_access"] == "public":
        required_tls = "domain" if value["web_mode"] == "domain" else "ip-trusted"
        if value["tls_mode"] != required_tls:
            raise ValueError("Публичная панель требует доверенного TLS для выбранного адреса.")
    elif value["tls_mode"] != "private":
        raise ValueError("Для закрытого доступа используйте private TLS policy.")
    normalized["web_host"] = host
    for name in ("vpn_port", "backend_port"):
        port = value.get(name, DEFAULTS[name])
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("VPN-порты должны быть целыми числами от 1024 до 65535.")
    if value.get("vpn_port", DEFAULTS["vpn_port"]) == value.get("backend_port", DEFAULTS["backend_port"]):
        raise ValueError("Порты FreeTurn и WireGuard должны различаться.")
    try:
        subnet = ipaddress.ip_network(value.get("subnet", DEFAULTS["subnet"]), strict=True)
    except (ValueError, TypeError):
        raise ValueError("Некорректная подсеть VPN.") from None
    ranges = [ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if subnet.version != 4 or subnet.prefixlen != 24 or not any(subnet.subnet_of(item) for item in ranges):
        raise ValueError("Нужна частная IPv4-подсеть /24.")
    # Preserve whether a network value was explicitly requested. Migration may inherit other values.
    return normalized


def inspect_state(state):
    validate_legacy_state(state)
    app = baseline_module()
    return {"schema_version": 1, "instance": state["instance"], "endpoint": state["endpoint"],
            "vpn_port": state["port"], "backend_port": state["backend_port"], "subnet": state["subnet"],
            "interface": app.iface(state), "services": list(app.units(state)),
            "device_count": len(state["clients"]), "legacy_fixed_devices": True,
            "secrets_included": False, "runtime_health_checked": False}


def build_plan(config, existing_state=None):
    config = validate_config(config)
    network = {**DEFAULTS, **{key: config[key] for key in DEFAULTS if key in config}, "backend_public": False}
    legacy = None
    if existing_state is not None:
        legacy = inspect_state(existing_state)
        if config["mode"] == "fresh":
            raise ValueError("Обнаружена существующая установка: выберите migrate или repair.")
        for field in DEFAULTS:
            if field in config and config[field] != legacy[field]:
                raise ValueError("Миграция сохраняет порты и подсеть существующей установки.")
            network[field] = legacy[field]
    elif config["mode"] != "fresh":
        raise ValueError("Для migrate/repair требуется проверенное состояние Vps через --state.")
    return {
        "schema_version": 1, "stage": "planning_only", "changes_system": False, "apply_available": False,
        "mode": config["mode"], "web": {key: config[key] for key in ("web_mode", "web_host", "panel_access", "tls_mode")},
        "network": network, "existing_installation": legacy,
        "preserve": ["wireguard_keys_and_psks", "client_ids", "vk_link", "obfuscation_key", "existing_profiles",
                     "vpn_endpoint", "ssh", "firewall", "fail2ban", "unknown_peers_and_services"],
        "required_before_apply": ["ubuntu_24_04_preflight", "encrypted_offsite_backup_and_restore_check",
                                  "dns_and_trusted_tls_validation", "port_conflict_check",
                                  "rollback_implementation", "real_vpn_compatibility_tests"],
        "warnings": ["План не подтверждает DNS, сертификаты, доступность портов или работу VPN.",
                     "Установка Manager пока недоступна; системные изменения не выполнялись."],
    }
