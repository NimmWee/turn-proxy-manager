# Windows0.27: review установщика

Самостоятельная проверка после bounded AWG2/3 блока; субагенты запрещены пользователем. Реальные службы/registry startup/установку ночью не менять. Найденные ограничения0.26: installer guard намеренно отказывал любой частичной установке, из-за чего нельзя удалить даже единственную подтверждённо собственную idle службу; удаление вызывало core только при наличии broker. Кроме того, cleanup запрашивал SET_VALUE для каждого загруженного Run hive до установления принадлежности записи.

План законченного небольшого блока:

- [x] Критичная граница retained data: fresh install при пустом SCM не должен перезаписывать owner.sid и открывать сохранённый SYSTEM-DPAPI profile другому Windows SID. Read-only owner guard до directory/ACL/legacy rule/service mutations; unknown nonempty data без owner отказывать, прежнего owner допускать. Targeted filesystem scenario подтверждает refusal без изменения profile/owner.

- [x] Разделить install guard и explicit uninstall guard: install по-прежнему отказывает partial; uninstall допускает только owned+idle partial, отказывает любой foreign/active/transitioning записи. До mutating core call проверить protected owner metadata и code path; не усыновлять неизвестные службы.
- [x] Вызвать fixed core --uninstall при наличии хотя бы одной своей службы; после этого подтвердить обе отсутствующими до удаления files/startup. Не удалять profile/ProgramData.
- [x] Run cleanup: сначала QUERY_VALUE; неизвестные/недоступные чужие hives не править; SET_VALUE открывать только для точного owned command, повторно сверить перед удалением. Targeted isolated HKCU test-key scenario подтверждает чужую запись preserved/свою deleted; настоящий Run path не используется тестом.
- [x] Risk tests/vet/build, read-only actual guard nonmutation/отказ cache mutation. Отдельный versioned0.27 ZIP+Setup, сохранить0.26 и более ранние. Реальные uninstall/repair/UAC/VM gates остаются NOT RUN.

Новых root VPN install/apply, пользовательских вопросов, production keys/feed или реального VPN здесь нет. Это hardening кода поставки, не утверждение о clean-host acceptance.

## Проверенный результат

Реализованы distinct install/removal gates и protected metadata проверка перед mutating uninstall; partial owned idle cleanup допускается без усыновления unknown services. Fixed core вызов проверяет любую присутствующую службу, затем подтверждает обе отсутствующими. Run cleanup сначала query-only, write только для exact owned command с повторной сверкой; недоступные чужие hives пропускаются.

Критичный retained-owner guard подключён в root install до SCM/ACL/legacy WFP/system writes: после удаления служб прежние SYSTEM-encrypted profile/owner не перепривязываются другому Windows SID. Unknown nonempty storage без owner отказывает; прежний owner может переустановить ядро. Test fixtures подтвердили отказ без изменения profile/owner bytes; реальный root install не запускался.

Red→PASS targeted guards/ordering/ownership tests; isolated **новый HKCU test-key**, без обращения к настоящему Run key, подтвердил foreign value preserved/owned deleted. Test-key удалён; остаточных FreeTurnSetupCheck_* ключей нет. Go tests/vet/build и WPF publish PASS; offline native CLI/routes/adapters/services digest unchanged. Actual SetupGuard --check-install READY, cache --remove-services refused17 до любых root действий. Никакой UAC/Setup/VPN/service mutation ночью.

ZIP0.27:90.45MiB,16 entries/15 payloads,215 corresponding source files,81 notices, SHA256 `39916251412f85cf85dbd63b7cb6c2c5d99adf5dddfb65ae06f880b7b0cfec73`. Setup0.27:79.54MiB, SHA256 `003c9b0512bfc3e1f2f60ed633c98f785319c38e19d8f84d300950f379e6d9c4`; setup sources `c30572fbb96da7d9db2004d5c79b6437bd122fb54441e83e040c3122b7137b88`. Source/hash/current/historical archives checks PASS; frozen0.23–0.26 ZIP/Setup сохранены. Test Ed25519 Python→Go verifier на байтах Setup0.27 PASS; **production signature/feed не появились, Setup unsigned и не исполнялся**.

Реальные install/upgrade/reinstall under another SID/partial uninstall/cleanup/UAC/clean VM проверки —NOT RUN. Partial **install/upgrade** по-прежнему отказывает: этот блок делает безопасным explicit uninstall, не автоматическое восстановление любой неизвестной установки. Для repair пользователь может удалить подтверждённо своё idle ядро и затем установить от прежнего владельца; unknown ownership требует отдельного решения. Установленная0.24 не обновлялась, существующие профили/iPhone/другие VPN/VPS не трогались.
