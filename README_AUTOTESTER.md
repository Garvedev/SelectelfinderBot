# Auto VLESS Tester: Redmi A9 + Termux + sing-box

Это обновление заменяет ручную проверку VLESS через Telegram-кнопки на очередь авто-тестера.

## Схема

```text
Finder bot / VPS
  -> создает сервер
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
- Добавлена Telegram-команда `/test_status`.
- `/status` теперь показывает краткую статистику авто-тестера.
- `run_single_vless_test()` больше не ждет кнопки `Работает/Не работает`: он создает сервер и кладет VLESS в очередь.

## Настройки VPS `.env`

```env
TESTER_API_ENABLED=true
TESTER_API_HOST=0.0.0.0
TESTER_API_PORT=8787
TESTER_TOKEN=PASTE_LONG_RANDOM_TOKEN_HERE
TESTER_BATCH_SIZE=11
TESTER_LEASE_SECONDS=900
TESTER_MAX_ATTEMPTS=2
```

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

Если результат не совпал, был timeout или sing-box не запустился — задача получает fail. После `TESTER_MAX_ATTEMPTS` IP уходит в `banned_ips.txt`.

## Команды Telegram

```text
/status
/test_status
/create_servers
```

`/test_status` показывает очередь, последние результаты и состояние API.

## Web dashboard

Dashboard is served by the same tester API process.

```env
DASHBOARD_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=CHANGE_ME_LONG_PASSWORD
DASHBOARD_LOG_LINES=200
VLESS_QUEUE_DB=/opt/selectel-finder/vless_tests.sqlite3
```

Open in browser:

```text
http://YOUR_VPS_IP:8787/dashboard
```

The browser will ask for login and password using HTTP Basic Auth.

The dashboard shows:

- finder status;
- approved/candidate/ban counters;
- VLESS queue counters;
- latest tests;
- VPS log tail;
- Termux worker online/offline status;
- last Termux worker log tail from heartbeat.

Update `termux_vless_tester.py` on the phone too, because the dashboard receives phone status through `/worker_heartbeat`.
