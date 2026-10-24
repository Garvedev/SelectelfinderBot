# Selectel Finder

Основной режим развёртывания сейчас — watchdog Selectel: проверка состояния
сервера каждые 30 секунд и автоматическое включение. `deploy.sh` запускает
`swiftshield-watchdog.service` и отключает старый `finder.service`.
Настройка и диагностика описаны в разделе «SwiftShield watchdog» ниже.

Локальный Telegram-бот и web dashboard для поиска подходящих Selectel Floating IP, создания временных VLESS-серверов и проверки ключей телефоном через Termux worker.

Проект рассчитан на наш закрытый сценарий: без публичного сайта, без nginx и без HTTPS. Dashboard отдается тем же Python-процессом, что и API авто-тестера.

## Что умеет

- Искать Floating IP в выбранных регионах Selectel и сверять их с `ipwhitelist_safe_cidr.txt`.
- Вести локальные списки:
  - `ipwhitelist_safe_cidr.txt` - целевые IP/CIDR для поиска;
  - `good_ips.txt` - найденные IP-кандидаты;
  - `approved_vless_keys.txt` - подтвержденные рабочие VLESS-ключи;
  - `banned_ips.txt` - забаненные IP/подсети.
- Создавать временный Ubuntu-сервер в Selectel, привязывать найденный Floating IP и ставить VLESS-задачу в очередь.
- Выдавать задачи телефону через HTTP API: `/next_tests`, `/results`, `/worker_heartbeat`.
- Проверять VLESS на телефоне через `termux_vless_tester.py`.
- Управляться через Telegram и dashboard.
- Работать в ручном режиме или в полном авто-цикле:

```text
поиск IP -> создание серверов -> проверка телефоном -> сохранение ключей -> новый поиск
```

## Текущая структура

```text
finder_ru1.py              # точка входа, состояние, бизнес-логика и orchestration
telegram_handlers.py       # Telegram-команды и callback-кнопки
dashboard_server.py        # HTTP API, dashboard static files, API телефона
selectel_cloud.py          # OpenStack/Selectel: Floating IP, серверы, сети, security group
lists_store.py             # good_ips, banned_ips, approved_vless_keys
vless_queue.py             # SQLite очередь, worker heartbeat, audit, runtime settings
termux_vless_tester.py     # worker для телефона/Termux/sing-box
dashboard/index.html       # dashboard UI
dashboard/assets/app.js    # frontend logic
dashboard/assets/styles.css
README_AUTOTESTER.md       # подробности телефона и классов ошибок
requirements.txt
systemd/finder.service
deploy.sh
rc.example.sh
```

Файлы состояния создаются во время работы и не коммитятся:

```text
.env
ipwhitelist_safe_cidr.txt
good_ips.txt
banned_ips.txt
approved_vless_keys.txt
finder.log
vless_tests.sqlite3
vless_tests.sqlite3-*
*.tmp
.venv/
__pycache__/
```

## Установка

Python 3.10+.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

На Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Создай `.env` в корне проекта. Минимальный шаблон:

```env
TELEGRAM_BOT_TOKEN=...
TELEGRAM_ALLOWED_CHAT_ID=...
SOCKS5_PROXY=

OS_AUTH_URL=https://cloud.api.selcloud.ru/identity/v3
OS_PROJECT_ID=...
OS_PROJECT_NAME=
OS_USERNAME=...
OS_PASSWORD='...'
OS_USER_DOMAIN_NAME=Default
OS_PROJECT_DOMAIN_NAME=Default
OS_INTERFACE=public
OS_IDENTITY_API_VERSION=3
OS_COMPUTE_API_VERSION=2.72

TARGET_COUNT=11
REGIONS=ru-1,ru-2,ru-3,ru-6,ru-7,ru-8,ru-9
GOOD_IP_SYNC_INTERVAL=300
WHITELIST_MAX_BYTES=1048576

TESTER_API_ENABLED=true
TESTER_API_HOST=0.0.0.0
TESTER_API_PORT=8787
TESTER_TOKEN=PASTE_LONG_RANDOM_TOKEN_HERE
TESTER_BATCH_SIZE=11
TESTER_LEASE_SECONDS=900
TESTER_MAX_ATTEMPTS=2

DASHBOARD_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=CHANGE_ME
DASHBOARD_LOG_LINES=200

PROVISION_ENABLED=true
PROVISION_ORIGIN_IP=YOUR_ORIGIN_IP
PROVISION_VLESS_TEMPLATE='vless://UUID@{WHITE_IP}:443?...#candidate'
PROVISION_PREEMPTIBLE_REGIONS=ru-1,ru-3,ru-7,ru-8
PROVISION_ALLOW_NON_PREEMPTIBLE=false
PROVISION_SERVER_NAME_PREFIX=selectel-finder
PROVISION_IMAGE_NAME='Ubuntu 24.04 LTS 64-bit'
PROVISION_REQUIRE_LOCAL_DISK=true
PROVISION_AUTO_FLAVOR_FALLBACK=true
PROVISION_MAX_FLAVOR_ATTEMPTS=10
PROVISION_SERVER_WAIT_SECONDS=300
PROVISION_SETUP_WAIT_SECONDS=120
PROVISION_TCP_CHECK_ENABLED=true
PROVISION_TCP_CHECK_TIMEOUT=5
PROVISION_TCP_CHECK_RETRIES=6
PROVISION_DELETE_SERVER_AFTER_RESULT=true
PROVISION_DELETE_FAILED_FLOATING_IP=true
```

`TESTER_TOKEN` можно сгенерировать так:

```bash
python - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
```

## Проверка и запуск

```bash
python -m py_compile finder_ru1.py lists_store.py vless_queue.py selectel_cloud.py telegram_handlers.py dashboard_server.py termux_vless_tester.py
python finder_ru1.py
```

После запуска:

```text
Telegram bot -> polling
HTTP API     -> http://HOST:8787
Dashboard    -> http://HOST:8787/dashboard
```

Dashboard защищен Basic Auth из `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD`. Если пароль пустой, dashboard вернет `503`.

## Telegram-команды

```text
/help                 список команд
/status               статус поиска, очереди и регионов
/regions              выбор регионов кнопками
/upload               загрузить новый ipwhitelist_safe_cidr.txt
/cancel               отменить ожидание файла
/start                запустить поиск Floating IP
/stop                 остановить поиск и выключить полный авто-режим
/sync                 сверить good_ips.txt с Selectel
/create_servers      создать временные серверы для найденных кандидатов
/test_status          статистика авто-тестера
/test_stop            пауза выдачи задач телефону и создания серверов
/test_start           снять паузу
/log                  последние 200 строк finder.log или journalctl
```

`/start` делает реальные операции с Selectel Floating IP. Сначала лучше проверить `/status`, `/regions` и whitelist.

## Dashboard

Открывается по адресу:

```text
http://HOST:8787/dashboard
```

Основные вкладки:

- `Обзор` - состояние поиска, метрики, телефон, журнал действий.
- `Активные проверки` - только активные VLESS-задачи: `queued`, `testing`, `provisioning`. В таблице показывается собранный VLESS-ключ, его можно скопировать и проверить вручную.
- `Списки` - просмотр, редактирование, сохранение, загрузка и скачивание:
  - `ipwhitelist_safe_cidr.txt`;
  - `approved_vless_keys.txt`;
  - `good_ips.txt`;
  - `banned_ips.txt`.
- `Регионы` - диагностика по регионам.
- `Логи` - логи finder и телефона.
- `Настройки` - runtime-настройки без ручного редактирования `.env`.
- `Обслуживание` - bulk-действия и cleanup.

Журнал действий в dashboard прокручиваемый. Редкие maintenance-кнопки спрятаны в блок обслуживания.

## Runtime-настройки

Runtime-настройки хранятся в `vless_tests.sqlite3` и перекрывают `.env` до сброса.

Через dashboard можно менять:

- `TARGET_COUNT`
- `SELECTED_REGIONS`
- `GOOD_IP_SYNC_INTERVAL`
- `PROVISION_PREEMPTIBLE_REGIONS`
- `PROVISION_ALLOW_NON_PREEMPTIBLE`
- `PROVISION_SETUP_WAIT_SECONDS`
- `PROVISION_SERVER_WAIT_SECONDS`
- `PROVISION_MAX_FLAVOR_ATTEMPTS`
- `PROVISION_TCP_CHECK_ENABLED`
- `PROVISION_TCP_CHECK_TIMEOUT`
- `PROVISION_TCP_CHECK_RETRIES`
- `PROVISION_DELETE_SERVER_AFTER_RESULT`
- `PROVISION_DELETE_FAILED_FLOATING_IP`
- `TESTER_BATCH_SIZE`
- `TESTER_LEASE_SECONDS`
- `TESTER_MAX_ATTEMPTS`

Presets:

```text
safe_ru3_ru7
fast_test
reliable_provisioning
keep_failed_ip
```

## Как работает поиск

1. Бот выбирает случайный регион из выбранных.
2. Создает Floating IP.
3. Если IP попал в `banned_ips.txt`, сразу удаляет его.
4. Если IP входит в whitelist, сохраняет его в `good_ips.txt`.
5. Если не входит, удаляет Floating IP.
6. Когда кандидатов достаточно для свободных слотов, поиск останавливается.
7. В ручном режиме нужно нажать `/create_servers` или кнопку в dashboard.
8. В полном авто-режиме provisioning запускается сам.

`TARGET_COUNT` - это общее число рабочих ключей. Если нужно 11 ключей, а в `approved_vless_keys.txt` уже есть 4, бот ищет только 7 новых кандидатов.

## Проверка VLESS

Provisioning для каждого кандидата:

1. Создает временный Ubuntu-сервер в регионе IP.
2. Подбирает image, flavor и приватную сеть.
3. Создает/использует security group `selectel-finder-proxy`.
4. Открывает TCP/443.
5. Привязывает Floating IP через Neutron.
6. Через cloud-init запускает forwarding install script.
7. Собирает VLESS-ключ из `PROVISION_VLESS_TEMPLATE`.
8. Кладет задачу в SQLite-очередь.
9. Termux worker забирает задачу и отправляет результат.

Если ключ подтвержден, он сохраняется в `approved_vless_keys.txt`.

Если проверка не прошла, IP не банится автоматически. Он получает статус для ручного решения:

```text
ip_not_suitable
phone_tcp_unreachable
vless_failed
exit_ip_mismatch
phone_failed
provision_failed
error
```

Через dashboard можно нажать:

- `Повторить` - вернуть задачу в очередь или запустить provisioning заново.
- `Удалить IP` - удалить сервер/Floating IP, убрать IP из `good_ips.txt` и добавить подсеть в `banned_ips.txt`.

Если включено `PROVISION_DELETE_FAILED_FLOATING_IP=true`, failed Floating IP удаляется автоматически при ошибке создания/запрещенном регионе, и запись убирается из `good_ips.txt`.

Подробности телефона, статусов и Termux-настроек: [README_AUTOTESTER.md](README_AUTOTESTER.md).

## Termux worker

На телефоне:

```bash
pkg update && pkg upgrade -y
pkg install -y python curl sing-box termux-api
mkdir -p ~/selectel-tester
```

Скопируй `termux_vless_tester.py` в `~/selectel-tester/`.

Минимальный запуск:

```bash
export TESTER_API_BASE="http://HOST:8787"
export TESTER_TOKEN="PASTE_LONG_RANDOM_TOKEN_HERE"
export CONTROL_VLESS='vless://YOUR_WORKING_CONTROL_KEY'
export WORKER_ID="redmi-a9"

termux-wake-lock
python ~/selectel-tester/termux_vless_tester.py
```

## API

Для телефона нужен заголовок:

```text
X-Tester-Token: TESTER_TOKEN
```

Endpoints:

```text
GET  /health
GET  /next_tests?worker=redmi-a9&limit=11
POST /worker_heartbeat
POST /results
```

Dashboard API находится под `/dashboard/api/...` и требует Basic Auth.

## Deploy через systemd

Типовой путь на сервере:

```text
/opt/selectel-finder
```

Первичная установка:

```bash
sudo mkdir -p /opt/selectel-finder
sudo chown "$USER:$USER" /opt/selectel-finder
cd /opt/selectel-finder
```

После копирования проекта и `.env`:

```bash
sudo ./deploy.sh
```

Управление сервисом:

```bash
sudo systemctl status swiftshield-watchdog --no-pager
sudo systemctl restart swiftshield-watchdog
sudo systemctl stop swiftshield-watchdog
sudo journalctl -u swiftshield-watchdog -f
```

## SwiftShield watchdog

`swiftshield_watchdog.py` — отдельный watchdog для сервера `SwiftShield1`.
Его нужно запускать **на другом сервере**, который продолжит работать при
выключении SwiftShield1. Для постоянного режима используется `--loop`;
без флага выполняется одна проверка.

Добавь в `.env` (ID замени на ID своего сервера):

```env
SWIFTSHIELD_ENABLED=true
SWIFTSHIELD_REGION=ru-3
SWIFTSHIELD_AVAILABILITY_ZONE=
SWIFTSHIELD_SERVER_ID=YOUR_SERVER_UUID
SWIFTSHIELD_SERVER_NAME=SwiftShield1
SWIFTSHIELD_NOTIFY_TELEGRAM=true
SWIFTSHIELD_CHECK_INTERVAL_SECONDS=30
SWIFTSHIELD_API_TIMEOUT=10
SWIFTSHIELD_WAIT_SECONDS=0
SWIFTSHIELD_OPENSTACK_PROXY=
SWIFTSHIELD_OPENSTACK_PROXY_FALLBACK_TO_SOCKS5_PROXY=false
```

Нужны также параметры `OS_AUTH_URL`, `OS_PROJECT_ID` или `OS_PROJECT_NAME`,
`OS_USERNAME`, `OS_PASSWORD` из `.env.example`. Для уведомлений нужны
`TELEGRAM_BOT_TOKEN` и `TELEGRAM_ALLOWED_CHAT_ID`.

Проверка без изменения сервера, состояния watchdog и отправки уведомлений:

```bash
cd /opt/selectel-finder
. .venv/bin/activate
python swiftshield_watchdog.py --dry-run
```

Установка или обновление службы:

```bash
sudo bash deploy_swiftshield_watchdog.sh
sudo systemctl status swiftshield-watchdog.service --no-pager
sudo journalctl -u swiftshield-watchdog.service -n 100 --no-pager
```

Скрипт отключает прежний `.timer`, устанавливает постоянный сервис и
перезапускает его, чтобы обновления применились сразу. `deploy.sh` после
обновления git вызывает тот же установщик; GitHub Actions использует его же.
При push в `main` CI сначала обновляет код на хосте, затем запускает установщик
из актуальной версии с `APP_DIR=DEPLOY_PATH`. Ручная установка служб не нужна.
Установщик проверяет конфигурацию без запросов к Selectel, отключает старые
`finder.service` и таймер watchdog, включает автозагрузку и проверяет работу
новой службы. Если конфигурация неполная, watchdog выключен или включён
dry-run, деплой завершается ошибкой до остановки старых служб.
Параметры берутся из существующего GitHub Secret `ENV_FILE`; новые secrets
для этой миграции не нужны. Интервал по умолчанию — 30 секунд.

Проверка начинается сразу, затем каждые 30 секунд от начала предыдущей.
Запуск не блокирует следующие проверки даже при старом
`SWIFTSHIELD_WAIT_SECONDS=300`. Если API вернул ошибку, следующая проверка
повторит попытку. Пока `task_state` не пуст, новые команды не отправляются.
Если API или уведомления работают дольше интервала, пропущенные интервалы
пропускаются: параллельных запросов и серии догоняющих запусков нет.
`SWIFTSHIELD_API_TIMEOUT` ограничивает отдельный запрос, а не весь цикл.

| Состояние | Действие |
| --- | --- |
| `ACTIVE` | Проверка выполнена, включение не требуется |
| `SHUTOFF`, `STOPPED` | `start_server` |
| `SHELVED`, `SHELVED_OFFLOADED`, `EXPIRED` | `unshelve_server` |
| `PAUSED` | `unpause_server` |
| `SUSPENDED` | `resume_server` |
| Переходное состояние или непустой `task_state` | Повторная проверка в следующем цикле |
| `ERROR` или неизвестное состояние | Ошибка в журнале и уведомление; требуется диагностика |

Watchdog не выключает, не пересоздаёт и не перезагружает сервер.
`SWIFTSHIELD_SERVER_ID`, если задан, имеет приоритет: при ошибке запроса по ID
бот не переключается на другой сервер с таким же именем.
Если операция облака не меняется более 300 секунд, бот отправляет уведомление
о зависшей операции; порог — `SWIFTSHIELD_OPERATION_TIMEOUT_SECONDS`.
Для `SWIFTSHIELD_AVAILABILITY_ZONE` при unshelve нужен
`OS_COMPUTE_API_VERSION=2.77` или выше и поддержка этой версии облаком.
Обычно зону следует оставить пустой.

По умолчанию проверяется состояние ВМ через API. Для дополнительной проверки
прикладного TCP-порта укажи `SWIFTSHIELD_HEALTH_HOST` (IP или DNS),
`SWIFTSHIELD_HEALTH_PORT=443`, `SWIFTSHIELD_HEALTH_TIMEOUT=3`.
Закрытый порт у работающей ВМ приводит к уведомлению, без перезагрузки ВМ.
Открытый TCP-порт сам по себе не подтверждает корректность VLESS или приложения.

Состояние записывается в `SWIFTSHIELD_STATE_FILE`: последняя проверка,
изменения статуса, запрос восстановления и подтверждённое достижение `ACTIVE`.
`last_launch_at` обновляется после наблюдения `ACTIVE`, а не после принятия
команды API. При новом выключении уведомление снова приходит, даже если
предыдущее восстановление было менее часа назад.
Отказ Telegram не прерывает проверки.

По умолчанию watchdog подключается к OpenStack напрямую и удаляет
унаследованные HTTP/SOCKS proxy из своего окружения. Если требуется отдельный
независимый прокси, задай `SWIFTSHIELD_OPENSTACK_PROXY` или `OPENSTACK_PROXY`.
Прокси на самом SwiftShield1 для восстановления не подходит.

Прерываемый сервер Selectel может быть остановлен в любой момент при нехватке
ресурсов. После восстановления он остаётся прерываемым. При локальном
загрузочном диске восстановление не сохраняет данные диска — это свойство
услуги, watchdog не может его изменить.
См. [описание прерываемых серверов](https://docs.selectel.ru/cloud-servers/about/preemptible-servers/)
и [восстановление](https://docs.selectel.ru/cloud-servers/manage/restore-preemptible-server/).

Локальные проверки:

```bash
python -m unittest discover -s tests -v
bash -n deploy.sh deploy_swiftshield_watchdog.sh
```

## Безопасность

- Не коммить `.env`, SQLite, логи и списки состояния.
- Если токен Telegram, `TESTER_TOKEN` или пароль Selectel попал в git или чат, перевыпусти его.
- Dashboard локальный для нас, но пароль все равно обязателен.
- Перед запуском `/start` помни: бот создает и удаляет реальные Selectel Floating IP.

## Быстрый сценарий

1. Запустить `python finder_ru1.py` или systemd service.
2. В Telegram проверить `/status`.
3. Загрузить whitelist через `/upload`.
4. Выбрать регионы через `/regions`.
5. Запустить Termux worker.
6. Открыть `/dashboard`.
7. Нажать `Включить авто` или вручную: `/start`, затем `/create_servers`.
8. Следить за `Активные проверки`, логами и списками.
9. Проблемные IP решать через `Повторить` или `Удалить IP`.
