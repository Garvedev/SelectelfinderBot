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
- Dashboard показывает кнопки `Повторить` и `Удалить IP` для `phone_failed`, `provision_failed`, `rejected`, `error`.

## Безопасные статусы

```text
queued              задача ждет телефона
testing             задача выдана телефону
provisioning        идет ручной retry provisioning
approved            телефон подтвердил ключ
phone_failed        телефон не подтвердил ключ, IP НЕ забанен
provision_failed    сервер/VLESS/TCP/443 не подготовились, IP НЕ забанен
manual_banned       IP удален и забанен вручную через dashboard
rejected            legacy-статус старых записей
error               внутренняя ошибка, требуется ручное решение
```

`phone_failed` и `provision_failed` не возвращаются в очередь автоматически. Повторная проверка делается только вручную через dashboard.

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
- добавляет IP в banned_ips.txt;
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

## Важная логика для белых списков

Телефон не пытается переключать весь Android с одного ключа на другой.

Он держит два независимых локальных proxy:

```text
127.0.0.1:20808 -> control VLESS, всегда для связи с ботом
127.0.0.1:20809 -> test VLESS, только для проверки кандидата
```

Если test VLESS плохой, телефон не теряет связь с ботом, потому что control VLESS продолжает работать отдельно.

## Критерий успеха

Кандидат считается рабочим, только если:

```text
curl через test proxy вернул внешний IP, совпадающий с Floating IP кандидата
```

Если результат не совпал, был timeout или sing-box не запустился — задача получает `phone_failed`, но IP не банится автоматически.

## Диагностика

```bash
cd /opt/selectel-finder

curl http://127.0.0.1:8787/health

sqlite3 vless_tests.sqlite3 \
"select id, ip, region, status, attempts, worker, exit_ip, latency_ms, error from vless_tests order by id desc limit 20;"
```

Update `termux_vless_tester.py` on the phone too, because the dashboard receives phone status through `/worker_heartbeat`.
