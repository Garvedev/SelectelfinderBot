# Selectel Finder Bot

Telegram-бот для поиска подходящих Selectel Floating IP, загрузки целевого списка IP/CIDR из файла, выбора регионов поиска и автоматической проверки найденных IP через временные облачные серверы.

Бот работает с OpenStack API Selectel, создает и удаляет Floating IP, ведет списки найденных, забаненных и подтвержденных IP, а после заполнения свободных слотов может создать временный Ubuntu-сервер, установить forwarding-скрипт, поставить VLESS-ключ в очередь авто-тестера и принять результат от телефона через Termux worker.

Управлять можно из Telegram и из web dashboard. В dashboard есть ручной режим и полный авто-режим: поиск IP -> создание серверов -> проверка телефоном -> новый поиск до заполнения `TARGET_COUNT` или остановки кнопкой.

## Возможности

- Управление из Telegram-группы или чата.
- Доступ только для одного разрешенного `TELEGRAM_ALLOWED_CHAT_ID`.
- Загрузка файла с IP/CIDR только после команды `/upload`.
- Выбор регионов поиска кнопками через `/regions`.
- Поиск Floating IP только из загруженного whitelist.
- Бан-лист плохих подсетей: новый ручной бан сохраняется как IPv4 `/24`.
- Добор только свободных слотов: если уже есть 4 рабочих ключа из 11, бот ищет только 7 новых кандидатов.
- Автоматический provisioning временного сервера в Selectel для проверки VLESS.
- Создание preemptible-сервера там, где Selectel поддерживает этот тип.
- Очередь авто-тестера `vless_tests.sqlite3` для выдачи задач телефону.
- Termux worker для проверки VLESS через отдельный test proxy.
- Web dashboard с метриками, логами, настройками, bulk-действиями и полным авто-режимом.
- Сохранение рабочих ключей в локальный файл.
- Автоудаление временного сервера после проверки.

## Структура проекта

```text
.
├── .github/
│   └── workflows/
│       └── deploy.yml            # GitHub Actions deploy workflow
├── .env.example                  # пример конфигурации без секретов
├── .gitignore
├── finder_ru1.py                 # основной Telegram/OpenStack бот
├── ipwhitelist_safe_cidr.example.txt # пример списка целевых IP/CIDR
├── termux_vless_tester.py        # worker для Redmi/Termux/sing-box
├── README_AUTOTESTER.md          # подробная документация авто-тестера
├── requirements.txt              # Python-зависимости
├── deploy.sh                     # серверный deploy/update скрипт
├── rc.example.sh                 # пример Selectel OpenStack rc-файла
├── systemd/
│   └── finder.service            # systemd unit template
└── README.md
```

Файлы состояния создаются во время работы и не должны попадать в git:

```text
.env
rc_*.sh
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

## Требования

- Python 3.10+.
- Рабочий Telegram Bot Token.
- Selectel OpenStack пользователь с правами на проект.
- Доступ к OpenStack API Selectel.
- Для server deploy: Linux-сервер с `python3`, `python3-venv`, `systemd`, `git`.

Python-зависимости:

```text
python-openstackclient
openstacksdk
pyTelegramBotAPI
requests[socks]
python-dotenv
aiohttp
```

## Быстрый локальный запуск

1. Установить зависимости:

```powershell
cd C:\Users\artem\SelectelFinder
python -m pip install -r requirements.txt
```

2. Создать `.env` из примера:

```powershell
Copy-Item .env.example .env
```

3. Заполнить `.env`.

4. Проверить синтаксис:

```powershell
python -m py_compile finder_ru1.py
```

5. Запустить бота:

```powershell
python finder_ru1.py
```

В консоли должно появиться:

```text
🤖 Telegram бот запущен
```

Остановить локальный запуск можно через `Ctrl+C`.

## Настройка Telegram

Создайте бота через BotFather и укажите токен:

```env
TELEGRAM_BOT_TOKEN=...
```

Укажите chat id разрешенного чата:

```env
TELEGRAM_ALLOWED_CHAT_ID=-100...
```

Если бот работает в группе:

- добавьте бота в группу;
- отправьте `/status`;
- если бот отвечает, `TELEGRAM_ALLOWED_CHAT_ID` настроен верно.

Если Telegram доступен напрямую, оставьте proxy пустым:

```env
SOCKS5_PROXY=
```

Если нужен SOCKS5:

```env
SOCKS5_PROXY=socks5://user:password@host:port
```

## Proxy для Selectel/OpenStack API

`SOCKS5_PROXY` продолжает управлять Telegram. Для запросов OpenStack SDK к Selectel API можно задать отдельный proxy:

```env
OPENSTACK_PROXY=socks5h://user:pass@host:port
OPENSTACK_PROXY_FALLBACK_TO_SOCKS5_PROXY=true
OPENSTACK_NO_PROXY=127.0.0.1,localhost
```

Если VPS не может напрямую открыть `https://cloud.api.selcloud.ru/identity/v3`, но через SOCKS proxy работает, используйте `OPENSTACK_PROXY=socks5h://...`. Вариант с fallback тоже поддерживается:

```env
OPENSTACK_PROXY=
OPENSTACK_PROXY_FALLBACK_TO_SOCKS5_PROXY=true
SOCKS5_PROXY=socks5h://user:pass@host:port
```

Проверка прямого доступа:

```bash
curl -4 -v --connect-timeout 5 --max-time 10 https://cloud.api.selcloud.ru/identity/v3
```

Проверка через proxy:

```bash
curl -4 -v --proxy "$SOCKS5_PROXY" \
  --connect-timeout 10 \
  --max-time 20 \
  https://cloud.api.selcloud.ru/identity/v3
```

Не делайте `source .env` для shell-проверок: в `.env` есть значения с пробелами, например `PROVISION_IMAGE_NAME='Ubuntu 24.04 LTS 64-bit'`. Если нужно прочитать env из shell-скрипта, используйте Python и `dotenv_values`, а не `source`.

## Настройка Selectel/OpenStack

Минимальные настройки:

```env
OS_AUTH_URL=https://cloud.api.selcloud.ru/identity/v3
OS_PROJECT_ID=...
OS_PROJECT_NAME=
OS_USERNAME=...
OS_PASSWORD='...'
OS_USER_DOMAIN_NAME=...
OS_PROJECT_DOMAIN_NAME=...
OS_REGION_NAME=ru-1
OS_INTERFACE=public
OS_IDENTITY_API_VERSION=3
OS_COMPUTE_API_VERSION=2.72
```

Если пароль содержит `$`, `{`, `?`, `#` или другие специальные символы, лучше хранить его в одинарных кавычках:

```env
OS_PASSWORD='password$with$specials'
```

Если задан `OS_PROJECT_ID`, бот игнорирует `OS_PROJECT_NAME` при OpenStack-подключении.

## Основные настройки поиска

```env
TARGET_COUNT=11
REGIONS=ru-1,ru-2,ru-3,ru-6,ru-7,ru-8,ru-9
GOOD_IP_SYNC_INTERVAL=300
WHITELIST_MAX_BYTES=1048576
LOG_FILE=/opt/selectel-finder/finder.log
```

`TARGET_COUNT` означает общее количество рабочих ключей, а не количество новых IP на каждый запуск.

`LOG_FILE` можно не задавать. По умолчанию лог пишется в `finder.log` рядом с `finder_ru1.py`.

Пример:

- `TARGET_COUNT=11`;
- в `approved_vless_keys.txt` уже есть 4 рабочих ключа;
- бот будет искать только 7 новых кандидатов.

## Telegram-команды

```text
/help
```

Показать список команд.

```text
/status
```

Показать состояние поиска, количество принятых ключей, новых кандидатов, регионов и бан-листа.

```text
/upload
```

Включить режим ожидания файла со списком IP/CIDR.

```text
/cancel
```

Отменить ожидание файла.

```text
/regions
```

Открыть кнопки выбора регионов.

```text
/start
```

Запустить поиск. Команда начинает реальные операции с Selectel Floating IP.

```text
/stop
```

Остановить поиск.

```text
/sync
```

Сверить `good_ips.txt` с OpenStack и удалить устаревшие записи.

```text
/create_servers
```

Запустить создание временных серверов и постановку найденных кандидатов в очередь авто-тестера.

```text
/test_status
```

Показать состояние очереди авто-тестера, worker-статусы и последние результаты.

```text
/test_stop
/pause_testing
```

Поставить на паузу выдачу задач телефону и создание новых серверов. Уже выданная телефону задача может еще прислать результат.

```text
/test_start
/resume_testing
```

Снять паузу с выдачи задач и создания серверов.

```text
/log
```

Отправить последние 200 строк `finder.log`, а если файла нет — последние строки `journalctl -u finder`.

## Загрузка файла с IP/CIDR

Бот не обрабатывает случайные файлы в чате. Чтобы обновить список целей:

1. Отправьте:

```text
/upload
```

2. Отправьте файл как Telegram-документ.

3. Бот провалидирует файл и заменит `ipwhitelist_safe_cidr.txt`.

Файл может называться как угодно. Важно только содержимое.

Пример:

```text
1.2.3.4
5.6.7.0/24
8.8.8.8
```

Поддерживаются:

- IPv4-адреса;
- IPv4 CIDR;
- комментарии через `#`;
- разделители строк, пробелы, запятые и `;`.

Если в файле есть некорректная строка, бот отклонит весь файл и покажет первые ошибки.

## Выбор регионов

Команда:

```text
/regions
```

Откроет inline-кнопки. Можно:

- включать/выключать конкретные регионы;
- выбрать все регионы;
- завершить выбор кнопкой `Готово`.

Изменения регионов подхватываются рабочим циклом автоматически.

## Логика поиска IP

1. Бот выбирает случайный регион из выбранных.
2. Создает Floating IP в этом регионе.
3. Проверяет, входит ли IP в текущий whitelist.
4. Если IP подходит, сохраняет его в `good_ips.txt`.
5. Если IP не подходит, удаляет его из Selectel.
6. Если IP в `banned_ips.txt`, сразу удаляет его.
7. IP, которые уже есть в очереди авто-тестера или ждут ручного решения, не считаются свободными кандидатами.
8. Когда новых кандидатов достаточно для свободных слотов, в ручном режиме поиск останавливается и предлагает `/create_servers`; в полном авто-режиме сразу запускается VLESS-проверка.

## Слоты, approved и ban

`approved_vless_keys.txt` содержит рабочие ключи. Каждый IP в этом файле занимает один слот.

`banned_ips.txt` содержит забаненные подсети CIDR. Новый ручной бан IP сохраняется как подсеть `/24`, например `139.100.193.0/24`. Такие подсети:

- не считаются кандидатами;
- удаляются из `good_ips.txt`;
- при повторном выпадении любого IP из подсети сразу удаляются из Selectel.

`good_ips.txt` содержит новые подходящие IP-кандидаты, которые еще надо проверить.

## Dashboard

Dashboard доступен на том же HTTP API, что и авто-тестер:

```text
http://YOUR_VPS_IP:8787/dashboard
```

Для включения dashboard в `.env` нужны:

```env
DASHBOARD_ENABLED=true
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD=CHANGE_ME
DASHBOARD_LOG_LINES=200
```

Если `DASHBOARD_PASSWORD` пустой, dashboard вернет `503` и не откроется. Авторизация простая HTTP Basic Auth.

В dashboard есть:

- карточка `Finder` с кнопками `Старт`, `Стоп`, `Включить авто` / `Выключить авто`;
- карточки approved, queue, workers, metrics;
- таблица регионов;
- последние тесты с кнопками `Повторить` и `Удалить IP`;
- логи телефона и VPS;
- audit последних dashboard-действий;
- страница `/dashboard/settings` для runtime-настроек без редактирования `.env`.

Полный авто-режим делает цикл сам:

```text
поиск IP -> набор кандидатов -> создание серверов -> проверка телефоном -> новый поиск
```

Цикл продолжается до заполнения `TARGET_COUNT`, кнопки `Стоп` или `Выключить авто`. Кнопка `Стоп` выключает и обычный поиск, и полный авто-режим.

Runtime-настройки dashboard хранятся в `vless_tests.sqlite3` и перекрывают значения из `.env` до сброса. Доступные группы:

- Finder: `TARGET_COUNT`, `SELECTED_REGIONS`, `GOOD_IP_SYNC_INTERVAL`;
- Provisioning: preemptible-регионы, обычные серверы, ожидания, flavor attempts;
- TCP check: timeout/retries;
- Cleanup: удаление временного сервера и failed Floating IP;
- Phone worker: batch, lease, max attempts.

Presets:

```text
safe_ru3_ru7
fast_test
reliable_provisioning
keep_failed_ip
```

Bulk-действия:

```text
Удалить все IP не подходят
Retry все vless_failed
Регион в provision_failed
Удалить старые provision_failed
Reconcile dry-run
Cleanup stale temp servers
```

## Автоматическая VLESS-проверка

Provisioning запускается вручную через `/create_servers`, через кнопку создания серверов, либо автоматически при включенном полном авто-режиме.

Подробная схема VPS API, Termux worker и классов ошибок описана в `README_AUTOTESTER.md`.

Настройки:

```env
PROVISION_ENABLED=true
PROVISION_ORIGIN_IP=YOUR_ORIGIN_IP
PROVISION_VLESS_TEMPLATE='vless://UUID@{WHITE_IP}:443?...#user'
PROVISION_PREEMPTIBLE_REGIONS=ru-1,ru-3,ru-7,ru-8
PROVISION_ALLOW_NON_PREEMPTIBLE=false
PROVISION_SERVER_NAME_PREFIX=selectel-finder
```

Для каждого IP бот:

1. Создает сервер в той же локации, что и IP.
2. Выбирает Ubuntu image.
3. Выбирает самый маленький flavor с локальным диском.
4. Выбирает приватную сеть.
5. Создает или использует security group `selectel-finder-proxy`.
6. Добавляет правило TCP/443.
7. Подключает найденный Floating IP.
8. Через cloud-init выполняет установку forwarding.
9. Формирует VLESS-ключ с подстановкой IP.
10. Ставит VLESS-ключ в SQLite-очередь `vless_tests.sqlite3`.
11. Termux worker забирает задачу, проверяет ключ через test proxy и отправляет результат обратно в API.

Команды, которые выполняются на сервере через cloud-init:

```bash
curl -fsSLO https://raw.githubusercontent.com/denpiligrim/3dp-manager/main/forwarding_install.sh
export ORIGIN_IP="$PROVISION_ORIGIN_IP"
sudo -E bash forwarding_install.sh
```

После успешной проверки временный сервер удаляется, если включено:

```env
PROVISION_DELETE_SERVER_AFTER_RESULT=true
```

Если телефон подтвердил ключ:

- ключ сохраняется в `approved_vless_keys.txt`;
- IP занимает слот;
- бот переходит к следующему кандидату.

Если телефон не подтвердил ключ:

- IP получает статус `phone_failed`, `vless_failed`, `exit_ip_mismatch` или `ip_not_suitable`;
- IP не банится автоматически;
- решение принимается в dashboard кнопками `Повторить` или `Удалить IP`.

Если в dashboard нажать `Удалить IP`:

- подсеть IP сохраняется в `banned_ips.txt`;
- удаляется из `good_ips.txt`;
- Floating IP удаляется из Selectel, если включено:

```env
PROVISION_DELETE_FAILED_FLOATING_IP=true
```

## Preemptible-серверы

Selectel поддерживает preemptible-серверы не во всех регионах. По умолчанию бот считает такими регионами:

```env
PROVISION_PREEMPTIBLE_REGIONS=ru-1,ru-3,ru-7,ru-8
```

Если IP находится в другом регионе, provisioning по умолчанию не будет создавать обычный сервер.

Чтобы разрешить обычные серверы в остальных регионах:

```env
PROVISION_ALLOW_NON_PREEMPTIBLE=true
```

## Подбор image, flavor, network

По умолчанию бот пытается найти:

```env
PROVISION_IMAGE_NAME='Ubuntu 24.04 LTS 64-bit'
PROVISION_REQUIRE_LOCAL_DISK=true
```

Flavor выбирается автоматически: бот пробует самый маленький flavor по vCPU, RAM и disk, с локальным диском. Если Selectel возвращает ошибку вроде `The requested availability zone is not suitable for the requested instance type`, бот пробует следующий подходящий flavor.

По умолчанию бот больше не выбирает availability zone автоматически. Если `PROVISION_AVAILABILITY_ZONE` пустой, Selectel/OpenStack сам выбирает подходящую зону. Это снижает риск ошибки несовместимости зоны и типа инстанса.

Сеть выбирается автоматически: первая приватная сеть в регионе.

Настройки fallback-подбора flavor:

```env
PROVISION_AUTO_FLAVOR_FALLBACK=true
PROVISION_MAX_FLAVOR_ATTEMPTS=10
```

`PROVISION_AUTO_FLAVOR_FALLBACK=true` означает: если выбранный или самый маленький flavor не подошёл, бот попробует следующий.

`PROVISION_MAX_FLAVOR_ATTEMPTS=10` ограничивает количество попыток на один IP, чтобы бот не перебирал слишком много вариантов.

Если нужно зафиксировать ресурсы явно:

```env
PROVISION_IMAGE_ID=
PROVISION_FLAVOR_ID=
PROVISION_NETWORK_ID=
PROVISION_AVAILABILITY_ZONE=
PROVISION_AUTO_FLAVOR_FALLBACK=true
PROVISION_MAX_FLAVOR_ATTEMPTS=10
```

Можно задать региональные override-переменные. В суффиксе региона `-` заменяется на `_`:

```env
PROVISION_IMAGE_ID_RU_1=
PROVISION_FLAVOR_ID_RU_1=
PROVISION_NETWORK_ID_RU_1=
PROVISION_AVAILABILITY_ZONE_RU_1=
```


### Ошибка availability zone / instance type

Если Selectel возвращает:

```text
The requested availability zone is not suitable for the requested instance type
```

бот не останавливает весь процесс проверки. Он:

1. оставляет найденный Floating IP в `good_ips.txt`;
2. пишет ошибку в лог;
3. пробует следующий flavor;
4. если все попытки не подошли, отправляет ошибку в Telegram и переходит дальше.

Если нужно принудительно указать зону, можно задать:

```env
PROVISION_AVAILABILITY_ZONE=ru-3a
```

или регионально:

```env
PROVISION_AVAILABILITY_ZONE_RU_3=ru-3a
```

Если зона не указана, бот передаёт `availability_zone=auto` и позволяет Selectel выбрать подходящую зону самостоятельно.

## Server deploy через systemd

Рекомендуемый путь на сервере:

```text
/opt/selectel-finder
```

Первичная установка:

```bash
sudo mkdir -p /opt/selectel-finder
sudo chown "$USER:$USER" /opt/selectel-finder
cd /opt/selectel-finder
```

Далее скопировать проект или клонировать репозиторий, создать `.env` и запустить:

```bash
sudo ./deploy.sh
```

`deploy.sh` делает:

- `git pull --ff-only`, если папка является git-репозиторием;
- создание `.venv`;
- установку зависимостей;
- создание systemd unit из шаблона;
- `systemctl enable finder`;
- `systemctl restart finder`;
- вывод `systemctl status finder`.

По умолчанию сервис запускается от пользователя `finder`. Если проект лежит в `/root/...`, deploy автоматически переключит service user на `root`, потому что системный пользователь не сможет пройти внутрь `/root`.

## Управление сервисом

```bash
sudo systemctl status finder --no-pager
sudo systemctl restart finder
sudo systemctl stop finder
sudo journalctl -u finder -f
```

## Обновление на сервере

После push в git:

```bash
cd /opt/selectel-finder
sudo ./deploy.sh
```

Когда будет настроен автодеплой, этот же скрипт можно вызывать из webhook/CI.

## Проверки перед запуском

Локально:

```bash
python -m py_compile finder_ru1.py
python -m py_compile termux_vless_tester.py
python -c "import finder_ru1; print('import ok')"
```

Проверить Telegram без запуска поиска:

```text
/status
/help
/regions
```

Не отправляйте `/start`, пока не готовы к реальному созданию и удалению Floating IP.

## Безопасность

- Не коммитьте `.env`.
- Не коммитьте `good_ips.txt`, `banned_ips.txt`, `approved_vless_keys.txt`, `vless_tests.sqlite3`, `finder.log`.
- Если токен Telegram или пароль Selectel попал в переписку, скриншот или git, перевыпустите его.
- Храните OpenStack пароль в одинарных кавычках, если в нем есть `$`.
- Закрывайте dashboard паролем через `DASHBOARD_PASSWORD`; без него dashboard не откроется.
- Перед публичным push проверьте:

```bash
git status
git diff --cached
git diff
```

## Типовой сценарий работы

1. Запустить бота.
2. В Telegram отправить `/status`.
3. Отправить `/upload`.
4. Загрузить файл с IP/CIDR.
5. Настроить регионы через `/regions`.
6. Отправить `/start`.
7. Дождаться поиска новых кандидатов.
8. Отправить `/create_servers` или нажать кнопку создания серверов.
9. Дождаться, пока Termux worker проверит задачи.
10. Проблемные IP обработать в dashboard: `Повторить` или `Удалить IP`.
11. Повторять до заполнения `TARGET_COUNT` рабочих ключей.

Полностью автоматический сценарий:

1. Запустить бота и Termux worker.
2. Открыть `/dashboard`.
3. Нажать `Включить авто`.
4. Наблюдать за очередью, worker-статусом и логами.
5. Остановить цикл кнопкой `Стоп` или `Выключить авто`.

## GitHub Actions deploy

В проекте есть GitHub Actions workflow:

```text
.github/workflows/deploy.yml
```

Он запускается на push в `main` и вручную через `workflow_dispatch`.

Для работы нужно добавить в приватный GitHub repository secrets:

```text
DEPLOY_HOST       # IP или hostname сервера
DEPLOY_PORT       # SSH port, обычно 22
DEPLOY_USER       # пользователь для SSH
DEPLOY_SSH_KEY    # приватный SSH key без passphrase или key, поддерживаемый CI
DEPLOY_PATH       # путь к проекту на сервере, например /opt/selectel-finder
ENV_FILE          # полное содержимое .env для сервера
```

На сервере пользователь `DEPLOY_USER` должен уметь:

- заходить по SSH с этим ключом;
- читать приватный git-репозиторий;
- выполнять `sudo ./deploy.sh` без интерактивного ввода пароля.

Минимальная схема:

1. Создать приватный репозиторий.
2. Push проекта.
3. На сервере клонировать репозиторий в `DEPLOY_PATH`.
4. Создать серверный `.env`.
5. Один раз выполнить `sudo ./deploy.sh`.
6. Добавить GitHub secrets.
7. Следующие push в `main` будут запускать deploy автоматически.

Первичная последовательность:

1. Создать git-репозиторий.
2. Проверить `.gitignore`.
3. Сделать первый commit.
4. Создать remote.
5. Push проекта.
6. На сервере клонировать репозиторий в `/opt/selectel-finder`.
7. Настроить `.env` на сервере.
8. Запустить `sudo ./deploy.sh`.
9. Подключить webhook или CI, который будет вызывать deploy после push.
