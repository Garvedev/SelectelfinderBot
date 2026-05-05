# Auto VLESS Tester: Redmi A9 + Termux + sing-box

Это обновление заменяет ручную проверку VLESS через Telegram-кнопки на очередь авто-тестера и добавляет безопасный режим ручного решения для проблемных IP.

## Схема

```text
Finder bot / VPS
  -> создает сервер
  -> проверяет TCP/443 на Floating IP
  -> генерирует VLESS
  -> кладет задачу в SQLite queue

Redmi A9 / Termux
  -> держит CONTROL_VLESS на 127.0.0.1:20808
  -> через него получает до 11 задач
  -> каждый test VLESS запускает отдельно на 127.0.0.1:20809
  -> проверяет exit IP через https://api.ipify.org
  -> отправляет результат обратно через CONTROL_VLESS
```

## Что изменено на VPS

- Добавлена SQLite-очередь `vless_tests.sqlite3`.
- Добавлен HTTP API:
  - `GET /health`
  - `GET /next_tests?worker=redmi-a9&limit=11`
  - `POST /results`
  - `POST /worker_heartbeat`
- Добавлены Telegram-команды:
  - `/test_status`
  - `/test_stop` / `/pause_testing`
  - `/test_start` / `/resume_testing`
- `/status` теперь показывает краткую статистику авто-тестера и pause-состояние.
- `run_single_vless_test()` больше не ждет кнопки `Работает/Не работает`: он создает сервер и кладет VLESS в очередь.
- Ошибка телефона больше не банит IP автоматически. IP получает статус `phone_failed` и ждет ручного решения в dashboard.
- Ошибка создания сервера, cloud-init, TCP/443 или provisioning получает статус `provision_failed` и тоже ждет ручного решения.
- Dashboard показывает кнопки `Повторить` и `Удалить IP` для fail/review-статусов: `ip_not_suitable`, `vless_failed`, `exit_ip_mismatch`, `phone_failed`, `provision_failed`, `rejected`, `error`.
- Dashboard также умеет запускать/останавливать Finder и включать полный авто-режим.

## Безопасные статусы

```text
queued              задача ждет телефона
testing             задача выдана телефону
provisioning        идет ручной retry provisioning
approved            телефон подтвердил ключ
phone_failed        телефон не подтвердил ключ, IP НЕ забанен
ip_not_suitable     телефон не смог напрямую открыть TCP/443 к candidate IP
vless_failed        TCP есть, но VLESS/REALITY/curl через test proxy не прошел
exit_ip_mismatch    VLESS работает, но exit IP не совпал с выбранной политикой
provision_failed    сервер/VLESS/TCP/443 не подготовились, IP НЕ забанен
manual_banned       IP удален и забанен вручную через dashboard
rejected            legacy-статус старых записей
error               внутренняя ошибка, требуется ручное решение
```

Fail-статусы (`phone_failed`, `ip_not_suitable`, `vless_failed`, `exit_ip_mismatch`, `provision_failed`) не возвращаются в очередь автоматически. Повторная проверка делается вручную через dashboard.

## Настройки VPS `.env`

```env
TESTER_API_ENABLED=true
TESTER_API_HOST=0.0.0.0
TESTER_API_PORT=8787
TESTER_TOKEN=PASTE_LONG_RANDOM_TOKEN_HERE
TESTER_BATCH_SIZE=11
TESTER_LEASE_SECONDS=900
TESTER_MAX_ATTEMPTS=2
VLESS_QUEUE_DB=/opt/selectel-finder/vless_tests.sqlite3

PROVISION_TCP_CHECK_ENABLED=true
PROVISION_TCP_CHECK_TIMEOUT=5
PROVISION_TCP_CHECK_RETRIES=6
```

`TESTER_MAX_ATTEMPTS` теперь влияет в основном на lease/reissue для зависших `testing` задач. Обычный fail от телефона сразу переводит IP в `phone_failed`, без автоматического цикла retry.

Сгенерировать токен:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
```

После изменения `.env`:

```bash
cd /opt/selectel-finder
sudo ./deploy.sh
```

Проверка API с VPS:

```bash
curl http://127.0.0.1:8787/health
```

В ответе должны быть поля:

```json
{
  "ok": true,
  "testing_paused": false,
  "provisioning_paused": false,
  "full_auto_mode": false,
  "stats": {}
}
```

## Telegram-команды

```text
/status
/test_status
/test_stop
/test_start
/create_servers
```

`/test_stop`:

```text
- ставит на паузу выдачу задач телефону;
- ставит на паузу создание новых серверов;
- не убивает Termux;
- не удаляет текущие серверы/IP;
- уже выданная телефону задача может еще прислать результат.
```

`/test_start` снимает обе паузы.

## Dashboard actions

Dashboard доступен по адресу:

```text
http://YOUR_VPS_IP:8787/dashboard
```

В карточке `Finder` есть кнопки:

```text
Старт
Стоп
Включить авто / Выключить авто
```

`Старт` и `Стоп` запускают и останавливают тот же поиск IP, что команды `/start` и `/stop` в Telegram.

`Включить авто` запускает полный цикл: поиск IP -> создание серверов -> проверка телефоном -> новый поиск, пока не будет нажата кнопка `Стоп` или `Выключить авто`. При включении авто-режима выдача задач телефону и создание серверов снимаются с паузы.

Bulk-действия в dashboard:

```text
Удалить все IP не подходят
Retry все vless_failed
Регион в provision_failed
Удалить старые provision_failed
Reconcile dry-run
Cleanup stale temp servers
```

Для проблемных IP появляются кнопки:

```text
Повторить
Удалить IP
```

`Повторить`:

```text
phone_failed + server_id есть -> возвращает задачу в queued, attempts=0
provision_failed/error/rejected -> запускает повторное создание сервера
```

`Удалить IP`:

```text
- best-effort cleanup server;
- удаляет Floating IP в Selectel;
- удаляет IP из good_ips.txt;
- добавляет подсеть IP в banned_ips.txt, например 139.100.193.0/24;
- переводит запись в manual_banned.
```

## Настройка Termux

```bash
pkg update && pkg upgrade -y
pkg install -y python curl sing-box termux-api
mkdir -p ~/selectel-tester
```

Скопировать `termux_vless_tester.py` в `~/selectel-tester/`.

Запуск:

```bash
export TESTER_API_BASE="http://YOUR_VPS_IP:8787"
export TESTER_TOKEN="PASTE_LONG_RANDOM_TOKEN_HERE"
export CONTROL_VLESS='vless://YOUR_ALREADY_WORKING_CONTROL_KEY'
export WORKER_ID="redmi-a9"

termux-wake-lock
python ~/selectel-tester/termux_vless_tester.py
```

Дополнительные переменные Termux worker:

```bash
export TESTER_WORK_DIR="$HOME/selectel-tester"
export CONTROL_PROXY_PORT=20808
export TEST_PROXY_PORT=20809
export TESTER_BATCH_SIZE=11
export POLL_SLEEP=10
export HEARTBEAT_INTERVAL=30
export SINGBOX_STARTUP_WAIT=2.5
export CURL_TIMEOUT=20
export TEST_URL="https://api.ipify.org"
export DIRECT_TEST_URL="$TEST_URL"
```

Если результат не удалось отправить на VPS, worker складывает его в `pending_results.jsonl` внутри `TESTER_WORK_DIR` и пробует отправить позже.

## Важная логика для белых списков

Телефон не пытается переключать весь Android с одного ключа на другой.

Он держит два независимых локальных proxy:

```text
127.0.0.1:20808 -> control VLESS, всегда для связи с ботом
127.0.0.1:20809 -> test VLESS, только для проверки кандидата
```

Если test VLESS плохой, телефон не теряет связь с ботом, потому что control VLESS продолжает работать отдельно.

## Критерий успеха

Кандидат считается рабочим, если curl через test proxy успешно вернул внешний IP и результат проходит политику `TESTER_EXPECT_EXIT_IP`.

```text
any        принять любой непустой exit IP через test VLESS
candidate  требовать, чтобы exit IP совпал с Floating IP кандидата
exact      требовать, чтобы exit IP совпал с EXPECTED_EXIT_IP
```

Для текущего frontend/forwarding-сценария рекомендуется `TESTER_EXPECT_EXIT_IP=any`.

Если результат не проходит политику, был timeout или sing-box не запустился — задача получает fail-статус, но IP не банится автоматически.

## Диагностика

```bash
cd /opt/selectel-finder

curl http://127.0.0.1:8787/health

sqlite3 vless_tests.sqlite3 \
"select id, ip, region, status, attempts, worker, exit_ip, latency_ms, error from vless_tests order by id desc limit 20;"
```

Update `termux_vless_tester.py` on the phone too, because the dashboard receives phone status through `/worker_heartbeat`.

## Error classes in phone testing

The Termux worker now separates phone-side failures into actionable classes:

```text
phone_tcp_unreachable  Redmi could not open raw TCP to candidate_ip:443.
                       For the whitelist-search use case this means the IP is not reachable directly from the phone network.

vless_failed           TCP to candidate_ip:443 is reachable, but VLESS/REALITY or curl through the test proxy failed.
                       Check origin VLESS, REALITY parameters, forwarding/NAT, and sing-box compatibility.

exit_ip_mismatch       VLESS worked, but api.ipify.org returned an IP that does not match the configured expectation.

provision_failed       VPS/server preparation failed before the task was sent to the phone.
```

Recommended Termux settings for Selectel frontend/forwarding mode:

```bash
export TESTER_EXPECT_EXIT_IP=any
export RAW_TCP_CHECK_ENABLED=true
export RAW_TCP_CHECK_TIMEOUT=8
```

`TESTER_EXPECT_EXIT_IP` supports:

```text
any        accept any non-empty api.ipify.org result through the test VLESS
candidate  require exit IP to equal the candidate IP
exact      require exit IP to equal EXPECTED_EXIT_IP
```

For this project, `phone_tcp_unreachable` is a useful negative result: it means the phone network cannot directly reach that candidate IP on 443, so the IP should not be retried automatically. Use the dashboard buttons to delete/ban it or retry manually later.
