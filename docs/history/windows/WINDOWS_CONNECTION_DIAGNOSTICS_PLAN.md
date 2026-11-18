# Windows0.7: этапы подключения и обновление службы

16.11.2026. Пользователь сообщил: при отключённой Amnezia минуту показывалась попытка подключения, затем ничего; попросил больше состояний. Причина именно той попытки **не установлена**. Текущее read-only наблюдение: broker старый (capabilities отсутствуют), profile есть, tunnel stopped; нынешняя Amnezia вызывает preflight guard, но пользователь исключил её для неудачной попытки. UIA открытого elevated окна не дал текст. Не запускать VPN/обновление служб вместо пользователя.

Найдены две подтверждённые проблемы кода: raw core logs полностью отбрасываются, error state/SCM stop не сохраняет причину в UI; «Обновить службы» вызывает install, отказывающий поверх существующей установки. Исправляем обе без утверждения, что это доказанная причина сетевого сбоя.

- [x] Безопасная диагностика: только allowlisted stage/error codes, не raw logs/URLs/keys. Реальные core events + наблюдения SCM/handshake/egress, время этапа и последнее продвижение, ошибка после остановки. Poll mobile.GetState для Direct, где нет push OnState. Targeted synthetic privacy test PASS.
- [x] UI: текущий этап/потоки/elapsed, сообщение о долгом ожидании без fake процента/смены фазы по таймеру, переходы в очищенном журнале. Понятная завершённая ошибка и повторный Connect, если служба уже остановлена. Старой службе — явное уведомление об ограниченной диагностике. Renders420 PASS.
- [x] Fixed `--setup SID`: fresh install либо guarded upgrade. До mutation: existing owner совпадает, обе службы собственные и корректные, tunnel Stopped, package driver hash. Только stop/start собственного broker, backup binary/driver и rollback при неудаче; профили/owner/options не переписывать при upgrade, VPN не стартовать. Guard/synthetic rollback-order checks PASS, реальный UAC upgrade/SCM rollback NOT RUN.
- [x] Build/targeted checks/packaged offline scenario/renders PASS; версия0.7.0 и docs. Новая реальная попытка пользователя остаётся NOT RUN; причина прежнего сбоя не объявлена установленной. [Отчёт](WINDOWS_CONNECTION_DIAGNOSTICS.md).

Новый raw debug dump не добавляется. Всё без субагентов/VPS/GitHub; ключи/профили и другие VPN сохраняются.
