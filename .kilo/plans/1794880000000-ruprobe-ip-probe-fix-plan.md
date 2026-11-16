# RuProbe — план фикса прогона IP: 177.3.213.44

## 1. Цель

Исправить прогон голого IP через бота так, чтобы для `177.3.213.44` (и любого другого IP) результат был честным, быстрым и различимым:

- класс отказа ставится по фактам, а не по отсутствию данных;
- `блокировка по адресу/порту` отличается от `недоступность не по ТСПУ` и от `проблема сети`;
- прогон чёрной дыры занимает секунды, а не сумму всех таймаутов зондов;
- в отчёте видно, какие зонды пропущены, чем измерялась живость и что именно молчит.

Не цель этого плана: менять модель ТСПУ, добавлять обход DPI, добавлять мультиоператорность, добавлять планировщик подписок.

## 2. Воспроизведение (текущее поведение)

Вход: пользователь отправляет в Telegram `177.3.213.44`.

Путь сейчас:

1. `bot/src/ruprobe_bot/handlers.py:108-114` `handle_fallback` -> `_start_probe` -> `create_check`, статус `Проверяю 177.3.213.44…`, фоновая задача `_run_and_report`.
2. `_target_kind` даёт `TargetKind.NET`.
3. `_probes_for` (`handlers.py:280-287`): из `DEFAULT_PROBES` убираются `dns`, `doh`, добавляется `neighbors`. Итог: `tcp, sni, sni_control, tls_full, throughput, icmp, neighbors`.
4. `service.py:35` `DEFAULT_PROBES = [dns, tcp, sni, sni_control, tls_full, throughput, icmp]` — в нём нет `tcp_alt_ports` и `udp`, хотя агент их умеет.
5. `agent/internal/probe/runner.go:181-260` `Run` выполняет зонды строго последовательно, каждый со своим дедлайном `AGENT_TIMEOUT_MS=5000` мс (`settings.py:38`).
6. `agent/internal/queue/queue.go:186-230` цели батча тоже последовательны; параллелизм только между заданиями (8 воркеров).
7. `bot/src/ruprobe_bot/classifier.py` классифицирует факты, `rendering.py` строит rich-отчёт.

Наблюдаемый дефект на чёрной дыре: 5 независимых TCP-диалов (`tcp`, `sni`, `sni_control`, `tls_full`, `throughput`) по 5 с = около 25 с только на TCP-слое, плюс `icmp` 3 попытки, плюс `neighbors` 16 адресов. Прогресс при этом `0 из 1`, черновик почти бесполезен. Вердикт при этом легко становится `BLOCK_L3L4` с уверенностью 0.55-0.95, даже когда мертва вся сеть до префикса, а не конкретный адрес.

## 3. Диагностика: подтверждённые дефекты

### 3.1 Набор зондов для NET неполный и неверный

Файлы: `bot/src/ruprobe_bot/handlers.py:280-287`, `bot/src/ruprobe_bot/service.py:35`.

- `tcp_alt_ports` не запрашивается для IP. Классификатор при этом умеет сигналы `all_ports_dead` (вес 0.3) и `port_selective` (вес 0.25) — `classifier.py:119-128`, но они никогда не сработают для IP, потому что `alt_ports` пуст. Развести правило по порту и правило по адресу невозможно.
- `udp` не запрашивается для IP, хотя `result.go:146-157` `UDPFacts` и зонд `udp` есть в агенте (`runner.go:244-246`). Блокировка транспорта целиком не проверяется.
- `sni` и `sni_control` для голого IP бессмысленны: `runner.go:196-200, 228-233` — `sniOrHost` подставляет сам IP как SNI. ClientHello с SNI = IP-адрес — невалидный сигнал, его молчание ничего не говорит о DPI-листе по домену. Контрольная проба при этом сравнивает IP-SNI с `example.com` — сравнение некорректно.
- `throughput` для голого IP без сервиса почти всегда даёт `None` или шум: `tls.go: runThroughput` требует живого TLS/HTTP, которого на произвольном IP нет. В отчёте это выглядит как `—`, а время на попытку тратится.

### 3.2 Нет общего дедлайна и переиспользования TCP

Файлы: `agent/internal/probe/runner.go:216-242`, `agent/internal/probe/tcp.go:14-58`.

- Каждый зонд делает свой `DialContext` с полным `deadline`. Нет fast-fail: если `tcp` уже дал timeout, `sni`, `sni_control`, `tls_full`, `throughput` всё равно пробуют тот же адрес с нуля.
- Есть `dialTCP` (`tcp.go:42-58`), возвращающий живое соединение, но `Run` его не использует для `sni`/`tls_full`/`throughput` — вместо этого каждый зонд диалит заново через `tcpDial`.
- Нет общего контекста на цель: сумма таймаутов зондов >> `timeout_ms`, заявленного в `POST /probe/batch`.

### 3.3 ICMP-fallback загрязняет живость

Файлы: `agent/internal/probe/icmp.go:58-103, 134-198`.

- `icmpOnce` при недоступности raw-сокета деградирует до TCP-connect на 443/80 (`icmpFallback`). Поле `Error` говорит о деградации, но `ICMPFacts.Alive` при этом ставится `true`, а `NeighborsFacts.Alive` считается по тому же `icmpOnce`.
- Следствие: `ICMP отвечает` в классификаторе может означать `TCP 443 открыт`, а не `ICMP жив`. Для `neighbors` это же искажение: сосед считается живым по TCP, хотя ICMP мёртв.
- В `compose.yaml` у агента уже есть `cap_add: NET_RAW`, но локальный запуск `go run ./cmd/agent` без прав и запуск без этого capability дают разное поведение одного и того же зонда, и это нигде не фиксируется в фактах.

### 3.4 Классификатор: мёртвая сеть превращается в BLOCK_L3L4

Файлы: `bot/src/ruprobe_bot/classifier.py:76-81, 112-147`.

- `network_dead` считается как `icmp не alive И neighbors не alive`, сигнал `network_unreachable` (вес 0.5) добавляется в общий список, но дальше выполнение идёт в ветку L3/L4 и `_finalize(BLOCK_L3L4, signals, base=0.15)` суммирует все веса. Итог: мёртвый префикс + `syn_no_answer` 0.4 + `network_unreachable` 0.5 = уверенность до 0.95 за класс, который по смыслу должен быть `UNAVAILABLE_OTHER`.
- `partial_neighborhood` (`classifier.py:131-134`) срабатывает при `neighbors.alive and neighbors.dead`, но `NeighborsFacts` (`result.go:179-187`) хранит только счётчики `Alive/Dead/Probed`, без доли и без списка, кто именно мёртв. Порог `часть соседей мертва` не определён.
- Без `tcp_alt_ports` ветка L3/L4 не может отличить `все порты мертвы` от `нет данных по другим портам`, но уверенность при этом не ограничивается. Нужен потолок уверенности при неполных данных и явная пометка в `notes`.
- `handshake_timeout` / `handshake_rst` (`classifier.py:149-160`) возвращают `UNAVAILABLE_OTHER` даже при `sni silent_drop` без `tcp_ok` — порядок веток надо пересмотреть после фаст-фейла.

### 3.5 Соседи: выборка и исключение цели

Файлы: `agent/internal/probe/icmp.go:200-223 samplePrefix`, `runner.go:250-256`.

- `samplePrefix` для `/24` при `limit=16` даёт шаг 15: `.1, .16, .31, .46...` — равномерная выборка, но сама цель `177.3.213.44` в неё не входит и отдельно не исключается, если совпадёт. Надо явно исключать целевой IP из кандидатов.
- `NeighborLimit` / `NeighborScope` из бота не передаются явно: `agent_client` / `run_check` не пробрасывают их, агент берёт дефолты из конфига. Это скрытая зависимость, её надо сделать явной через `Settings`.
- Нет поля `alive_ratio` / доли живых соседей в `NeighborsFacts` — классификатор и рендеринг вынуждены пересчитывать её из счётчиков.

### 3.6 Прогресс и отчёт не показывают, что происходит внутри цели

Файлы: `agent/internal/queue/queue.go:41-58, 265-272`, `bot/src/ruprobe_bot/handlers.py:185-199, 262-266`, `bot/src/ruprobe_bot/rendering.py:91-97, 208-217`.

- `Progress` только `completed/total` по целям. Для одной цели `total=1`, прогресс `0%` до самого конца. Черновик `DRAFT_INTERVAL_S=4` с при этом не даёт информации.
- `_transport_note` смотрит только на `tcp.reset_received / timeout_happened` из `ProbeResult` (`service.py:173-183` сохраняет только TCP-флаги). RST/TIMEOUT из `sni` и `tls_full` теряются, хотя в `raw` они есть.
- В таблице нет столбца `Соседи (alive/dead)` и нет пометки `зонд пропущен / ICMP через TCP-fallback`.

### 3.7 Баг фильтрации зондов в очереди

Файл: `agent/internal/queue/queue.go:193-199`.

- Цикл `for i, k := range kinds { if !k.Valid() { kinds = append(kinds[:i], kinds[i+1:]...) } }` мутирует срез во время итерации и пропускает следующий элемент после удалённого. При двух подряд неизвестных зондах второй не удаляется. Исправить на фильтрацию в новый срез.

## 4. Граница: antifilter.network НЕ используется

Это решение фиксируется в плане явно, потому что в разговоре прозвучал этот сервис.

Что такое antifilter.network (проверено 2026-11-16, страница `/ip`):

- Публикует списки IP из реестра РКН: `ip.lst` (100364 префикса, 196358 адресов), `ipsmart.lst` (суммаризация /32-/23, 21152 префикса), `ipsum.lst` (суммаризация /24, 21151 префикс), `subnet.lst` (7 префиксов), `ip6.lst`, `uablacklist.lst`, `govno.lst`, `custom.lst`.
- Источники списков: `reestr.rublacklist.net`, `github.com/zapret-info`, собственный резолв заблокированных доменов.
- Отдельно предлагает BGP-сессию и VPN (`/bgp`, `/vpn`).

Проект RuProbe этот сервис НЕ использует и в этом фиксе НЕ начинает использовать:

- Нет скачивания `ip.lst` / `ipsmart.lst` / `ipsum.lst` / `subnet.lst` и других списков, нет кэша списков, нет фонового обновления.
- Нет проверки `IP в списке antifilter` в классификаторе, нет веса сигнала из реестра, нет столбца в отчёте `в реестре / не в реестре`.
- Нет BGP-сессии с antifilter.network, нет VPN, нет проксирования проб через него.
- Нет зависимости от доступности `antifilter.network` / `antifilter.download`.

Почему:

- RuProbe по `docs/tspu-model.md`, раздел 5.4 — наблюдение живыми зондами, вердикт только вероятностный по сигнатурам. Членство в реестре — это не наблюдаемый факт сети, а внешнее утверждение о списке. Подмешивание его в классификацию превратило бы вероятностный вердикт в lookup по реестру.
- Списки неполные и устаревают: цикл распространения адреса в DPI-листах 5-15 минут, реестр и фильтры расходятся, в списках есть shared IP / CDN, где один адрес обслуживает и заблокированные, и незаблокированные ресурсы. Ложноположительный `в списке => заблокирован` противоречит модели.
- Это добавило бы внешнюю зависимость, задачу актуализации, хранения персональных списков и юридическую неоднозначность в проект, который сейчас намеренно stateless на стороне агента и observation-only.
- Если в будущем понадобится информационная сверка с реестром, это отдельное решение и отдельный план: только как аннотация в отчёте, никогда как сигнал классификатора, с явным указанием источника, даты списка и оговоркой. В этот фикс она не входит.

Зафиксировать решение в коде и доках:

- Добавить раздел в `docs/tspu-model.md` (раздел 5, границы) и в `README.md` (раздел Границы): `Реестры блокировок, в т.ч. antifilter.network, не используются: ни списки, ни BGP, ни VPN. Классификация — только по живым зондам.`
- Не добавлять новых зависимостей, env-переменных и сетевых вызовов к `antifilter.network`.

## 5. Фаза 1 — Набор зондов по виду цели (Python + Go, контракт)

Файлы: `bot/src/ruprobe_bot/service.py`, `bot/src/ruprobe_bot/handlers.py`, `agent/internal/probe/runner.go`, `agent/internal/httpapi/server.go`.

1. Вынести наборы зондов из `_probes_for` в `service.py` как именованные константы:
   - `DOMAIN_PROBES = [dns, doh, tcp, tcp_alt_ports, sni, sni_control, tls_full, throughput, udp, icmp, neighbors]`
   - `NET_PROBES = [tcp, tcp_alt_ports, udp, icmp, neighbors]` — без `dns/doh/sni/sni_control/throughput` по умолчанию.
   - `CIDR_PROBES` / `RANGE_PROBES` — как `NET_PROBES`, без `neighbors` на каждую цель (соседи берутся один раз на префикс, иначе шум).
2. Условные зонды второго этапа: `sni`, `sni_control`, `tls_full`, `throughput` для NET запускаются только если `tcp.connected` на 443. Реализовать как гейт в `runner.go: Run`: если `tcp` не connected, пропущенные зонды помечаются в `Result.Errors` как `skipped: tcp not connected`, а не как отсутствующие данные.
3. Пробросить `neighbor_limit` и `neighbor_scope` из `Settings` через `AgentClient.run_job` -> `POST /probe/batch` -> `queue.Volume`. Добавить в `Settings`: `neighbor_limit: int = 16`, `neighbor_scope: str = /24`, в `.env.example` и `compose.yaml`.
4. Обновить `HELP_TEXT` в `handlers.py:43-57`: перечислить актуальный набор для IP и домена, без обещания SNI-пробы для голого IP.

Критерий готовности: для `177.3.213.44` агент получает ровно `NET_PROBES`, для `example.com` — `DOMAIN_PROBES`; `tcp_alt_ports` и `udp` присутствуют в запросе для IP.

## 6. Фаза 2 — Агент: общий дедлайн, fast-fail, параллелизм (Go)

Файлы: `agent/internal/probe/runner.go`, `agent/internal/probe/tcp.go`, `agent/internal/probe/icmp.go`, `agent/internal/probe/tls.go`, `agent/internal/queue/queue.go`.

1. Ввести в `probe.Options` общий контекст на цель: `ctx, cancel := context.WithTimeout(ctx, deadline)` на всю `Run`, а не на каждый зонд отдельно. `deadline` — это `timeout_ms` из батча. Зависимые зонды при отмене контекста сразу возвращают `skipped`.
2. Fast-fail цепочка: `tcp` -> если `!connected`, пропустить `sni`, `sni_control`, `tls_full`, `throughput` без диала, зафиксировать причину. Если `tcp` connected, переиспользовать одно соединение для `sni`/`tls_full` там, где это возможно, либо как минимум переиспользовать факт `tcp.connected` и не диалить повторно для решения о запуске.
3. Параллелить независимые зонды внутри цели: `tcp` + `icmp` + `udp` + `neighbors` запускаются конкурентно (errgroup / `sync.WaitGroup`), `dns/doh` уже параллельны внутри `runDNS`. Зависимые (`sni` после `tcp`) остаются последовательными.
4. Исправить баг `queue.go:193-199`: фильтрация неизвестных `Kind` в новый срез, без мутации при итерации.
5. ICMP: добавить в `ICMPFacts` поле `method: icmp | tcp_fallback` и в `NeighborFact` то же. `Alive=true` только для настоящего ICMP; TCP-fallback даёт `alive=false`, `method=tcp_fallback`, `error=icmp unavailable: no raw socket`. Классификатор и рендеринг учитывают `method`.
6. Соседи: исключать целевой IP из кандидатов в `samplePrefix`/`runNeighbors`; добавить в `NeighborsFacts` `alive_ratio float64`; ограничить `limit` сверху значением из конфига, `scope` валидировать (`/24` или `/16`, иное -> `/24`).
7. Добавить в `JobState` опциональное поле `current_probe string` для прогресса внутри цели, обновлять его в `execute` перед каждым зондом, отдавать в `GET /jobs/{id}`. Бот использует его в черновике.

Критерий готовности: чёрная дыра `192.0.2.1` (TEST-NET-1, детерминированная) прогоняется за время не более `2 * timeout_ms + overhead neighbors`, а не `5 * timeout_ms`; `go test ./...` с тестом на время чёрной дыры проходит.

## 7. Фаза 3 — Классификатор (Python)

Файлы: `bot/src/ruprobe_bot/classifier.py`, `bot/tests/test_classifier.py`.

1. Ранний возврат для мёртвой сети: если `icmp.alive == False` и `neighbors.alive == 0` и `tcp.timeout_happened`, вернуть `UNAVAILABLE_OTHER` с сигналом `network_unreachable`, уверенностью не выше 0.65, и не добавлять веса L3/L4 поверх. Это исправляет дефект 3.4.
2. Для `BLOCK_L3L4` требовать минимум два независимых подтверждения: `syn_no_answer` + (`all_ports_dead` или `icmp_alive` с настоящим ICMP, не TCP-fallback). Без `tcp_alt_ports` в фактах — потолок уверенности 0.55 и `notes=Недостаточно данных: не проверены альтернативные порты`.
3. Учесть `icmp.method`: `icmp_alive` засчитывается только при `method == icmp`. При `method == tcp_fallback` добавлять сигнал `icmp_fallback_used` (вес 0.0, информационный) и не повышать уверенность L3/L4.
4. Соседи: ввести пороги явно — `neighbors_all_dead` (alive==0, probed>0), `neighbors_partial` (0 < alive < probed, доля живых 0.2-0.8), `neighbors_all_alive`. Веса: `all_dead` 0.2 только как поддержка, не как самостоятельный класс.
5. `throughput`: игнорировать `throughput` полностью, если `tls_full.tls_handshake == False`. Не давать `low_throughput` на пустом соединении.
6. Добавить сигналы `sni_skipped_for_ip`, `probes_skipped` в `Classification.notes`, чтобы отчёт объяснял, почему SNI не проверялся.
7. Тесты: синтетические наборы для `177.3.213.44`-подобных фактов:
   - все мёртво (tcp timeout, icmp dead, neighbors 0/16) -> `UNAVAILABLE_OTHER`, не `BLOCK_L3L4`;
   - icmp жив, все порты мертвы -> `BLOCK_L3L4` >= 0.7;
   - один порт жив, остальные мертвы -> `BLOCK_L3L4` с `port_selective`, либо `UNAVAILABLE_OTHER` при RST без alt-подтверждения;
   - RST на 443, остальные порты живы -> `UNAVAILABLE_OTHER`;
   - icmp через TCP-fallback -> уверенность L3/L4 не растёт.

Критерий готовности: все старые тесты проходят, новые тесты из пункта 7 проходят, уверенность никогда не достигает 1.0.

## 8. Фаза 4 — Бот, сервис, рендеринг (Python)

Файлы: `bot/src/ruprobe_bot/service.py`, `bot/src/ruprobe_bot/handlers.py`, `bot/src/ruprobe_bot/rendering.py`, `bot/src/ruprobe_bot/settings.py`, `bot/src/ruprobe_bot/agent_client.py`.

1. `service.py`: `save_results` сохранять `reset_received/timeout_happened` не только из `tcp`, но и OR по `sni`/`tls_full`; добавить в `TargetReport` поля `neighbors_alive`, `neighbors_dead`, `neighbors_probed`, `icmp_method`.
2. `handlers.py`: `_probes_for` делегировать в `service.py` (единый источник наборов), `_draft_text` показывать `current_probe` из снапшота, если он есть: `Проверяю 177.3.213.44: tcp_alt_ports…`.
3. `rendering.py`: `_transport_note` — раздельно `TCP: таймаут/RST`, `TLS: таймаут/RST`; в таблицу добавить столбец `Соседи` в формате `alive/dead`; в сноски добавить строку при `icmp_method == tcp_fallback`: `ICMP недоступен (нет raw-сокета), живость проверена через TCP — интерпретировать осторожно`; при пропущенных зондах — строку `Пропущено: sni, throughput — TCP не установился`.
4. `settings.py`: добавить `neighbor_limit`, `neighbor_scope`, `overall_timeout_ms` (если вводится в агенте) с дефолтами, пробросить в `.env.example`.
5. `agent_client.py`: пробросить `neighbor_limit/scope` в `submit_batch`, добавить поле `current_probe` в `JobSnapshot`/`JobProgress`.

Критерий готовности: rich-отчёт для одной IP-цели содержит таблицу с соседями, пометку о fallback/пропусках, disclaimer сохраняется последним блоком (`enforce_limits`).

## 9. Фаза 5 — Инфраструктура и доки

Файлы: `compose.yaml`, `.env.example`, `docs/tspu-model.md`, `README.md`, `tools/integration_check.py`.

1. Проверить `cap_add: NET_RAW` для агента в `compose.yaml` — без него ICMP в контейнере всегда будет fallback. Если capability нельзя дать, зафиксировать в доке, что ICMP в Docker — всегда fallback, и классификатор это учитывает.
2. В `docs/tspu-model.md` раздел 5 и 6: добавить пункт про antifilter.network (см. раздел 4 этого плана) и про fast-fail / общий дедлайн / ICMP-method.
3. В `README.md`: обновить раздел про классы и про то, что проверяется для IP vs домена; добавить границу про antifilter.network.
4. В `tools/integration_check.py`: добавить сценарий `177.3.213.44` как ручной (не assert на класс, потому что живой адрес может измениться), и детерминированный сценарий `192.0.2.1` с assert на время < `2*timeout` и на класс `UNAVAILABLE_OTHER` при мёртвых соседях.

## 10. Валидация (по плану, раздел 8)

Агент:
- `gofmt -l cmd internal` — чисто;
- `go build ./...`, `go vet ./...`;
- `go test ./...` — включая новые тесты: время чёрной дыры, фильтр `Kind`, исключение цели из соседей, `icmp method`.

Бот:
- `python -m pytest tests -q` — 32 старых + новые тесты классификатора, `_probes_for`, рендеринга;
- `alembic upgrade head` на пустой БД — миграция не требуется, если модель не меняется; если в `ProbeResult` добавляются поля, сделать миграцию `alembic revision --autogenerate`.

Интеграция:
- `docker compose config` — анкоры развернулись;
- `docker compose up --build` — оба сервиса поднялись (ранее демон Docker Desktop не был запущен, этот шаг не был проверен — выполнить явно);
- ручной прогон: `go run ./cmd/agent` + `python tools/integration_check.py`, затем `/check 177.3.213.44` в Telegram, проверить время, класс, таблицу соседей и сноски;
- рестарт агента посреди проверки — бот помечает проверку упавшей (уже покрыто).

## 11. Порядок исполнения

1. Фаза 1 (наборы зондов) — маленький, разблокирует всё остальное.
2. Фаза 2 (агент: дедлайн, fast-fail, ICMP-method, соседи, баг очереди) — основная работа.
3. Фаза 3 (классификатор) — после Фазы 2, потому что меняются факты.
4. Фаза 4 (бот/рендеринг) — после Фазы 3.
5. Фаза 5 (доки, antifilter-граница, интеграционный сценарий) — параллельно с 3-4, финальная проверка.

Не делать в этом фиксе: обход DPI, фрагментация ClientHello, туннели, интеграция с antifilter.network / реестрами, BGP, VPN, мультиоператорный интерфейс, планировщик подписок, PostgreSQL.

## 12. Риски

- Изменение набора зондов меняет сравнимость с историей в SQLite: старые проверки для IP не имели `tcp_alt_ports`/`udp`. В отчёте и в `notes` указывать версию набора зондов.
- Параллельный запуск зондов увеличивает нагрузку на цель и на сеть агента; ограничить конкурентность семафором (уже есть для соседей, добавить для зондов).
- `CAP_NET_RAW` может быть недоступен в окружении пользователя — тогда ICMP всегда fallback, и это должно быть видно в фактах, а не молча.
- Живой `177.3.213.44` принадлежит зарубежному оператору (BR, Telefônica/Vivo, AS27699), его доступность из РФ может меняться независимо от ТСПУ. Интеграционный тест на нём — только ручной, без assert на класс.
