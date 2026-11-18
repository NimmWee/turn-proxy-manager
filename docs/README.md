# Документация FreeTurn Manager

- [Ручная приёмка Windows 0.27: подключение, установка и сохранность профилей](WINDOWS_ACCEPTANCE_0_27.md).
- [Windows0.27: retained owner, own partial cleanup и проверенная поставка](WINDOWS_SETUP_HARDENING_27.md).
- [Windows0.26/0.27: bounded AWG2/3 и реальная local crypto проверка](WINDOWS_AWG_26.md).
- [Ночной итог18.11](OVERNIGHT_2026_11_18_REPORT.md).

- [Подписанные обновления: offline verifier и открытая интеграция](WINDOWS_UPDATE_PROTOCOL.md).

- [Setup Windows0.25: поставка, защитные проверки и открытая реальная приёмка](WINDOWS_INSTALLER_PLAN.md).

- [Windows0.25: bounded AWG1 backend, импорт и границы поддержки](WINDOWS_AWG_PLAN.md).
- [Локальные замеры core: Direct/TURN, streams, CPU/alloc и A/B](CORE_LOCAL_BENCHMARKS.md).
- [Ночное поручение18.11 и следующая задача](OVERNIGHT_2026_11_18.md).

Для текущей работы достаточно этих документов:

- [Windows0.24: удаление постоянной блокировки сети](WINDOWS_LOCK_REMOVAL_PLAN.md).
- [Windows0.23 (история): доставка правил, блокировка сети и восстановление](WINDOWS_POLICY_LOCK_NETWORK_PLAN.md).
- [ТЗ](FreeTurn_Manager_TZ.md) — требования и приёмка.
- [Ход работ](PROGRESS.md) — что реализовано и что действительно проверено.
- [Остаток по ТЗ](REMAINING_WORK.md) — очередь разработки.
- [План реализации](IMPLEMENTATION_PLAN.md) — этапы проекта.
- [Windows: текущие исправления и UX](WINDOWS_POLISH_PLAN.md).
- [Windows0.9: результат и проверки](WINDOWS_POLISH.md).
- [Windows: оставшийся перенос функций](WINDOWS_FULL_PORT_PLAN.md).
- [Windows: текущая маршрутизация SOCKS5 и границы](WINDOWS_ROUTING.md).
- [Windows: общесистемная маршрутизация — реализация и передача](WINDOWS_SYSTEM_ROUTING_PLAN.md).
- [Windows0.11: приватность cache и локальные DNS-имена](WINDOWS_LAN_DNS_PLAN.md).
- [Windows0.13: managed обновления, отдельное сохранение и возврат](WINDOWS_MANAGED_REFRESH_PLAN.md).
- [Windows0.14: регистрация устройства и восстановление попытки](WINDOWS_ENROLLMENT_PLAN.md).
- [Восстановление и checkpoint](CHECKPOINT.md).

Исторические планы и отчёты Windows0.1–0.8 сохранены в [history/windows](history/windows/README.md). Это история решений/проверок, а не дополнительные текущие задания. Серверные отчёты по security, backup и восстановлению оставлены рядом с ТЗ: они нужны для эксплуатации и восстановления доступа.

Лицензии, dependency locks и соответствующие исходники — обязательные части поставки. Старые ZIP-сборки находятся в `clients/windows/artifacts/`; они сохранены для отката. `bin/obj`, Python bytecode, `node_modules` и временные QA-результаты воспроизводимы и не являются исходниками.
