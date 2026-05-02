# Selectel Finder Bot

Telegram-бот для поиска подходящих Selectel Floating IP, загрузки целевого списка IP/CIDR из файла, выбора регионов поиска и автоматической проверки найденных IP через временные облачные серверы.

Бот работает с OpenStack API Selectel, создает и удаляет Floating IP, ведет списки найденных, забаненных и подтвержденных IP, а после заполнения свободных слотов может создать временный Ubuntu-сервер, установить forwarding-скрипт и отправить VLESS-ключ в Telegram на ручную проверку.

## Возможности

- Управление из Telegram-группы или чата.
- Доступ только для одного разрешенного `TELEGRAM_ALLOWED_CHAT_ID`.
- Загрузка файла с IP/CIDR только после команды `/upload`.
- Выбор регионов поиска кнопками через `/regions`.
- Поиск Floating IP только из загруженного whitelist.
- Бан-лист плохих IP: при повторном выпадении такие IP сразу удаляются.
- Добор только свободных слотов: если уже есть 4 рабочих ключа из 11, бот ищет только 7 новых кандидатов.
- Автоматический provisioning временного сервера в Selectel для проверки VLESS.
- Создание preemptible-сервера там, где Selectel поддерживает этот тип.
- Отправка VLESS-ключа в Telegram с кнопками `Работает` / `Не работает`.
- Сохранение рабочих ключей в локальный файл.
- Автоудаление временного сервера после проверки.

## Структура проекта

```text
.
├── finder_ru1.py                 # основной Telegram/OpenStack бот
├── ipwhitelist_safe_cidr.example.txt # пример списка целевых IP/CIDR
├── requirements.txt              # Python-зависимости
├── deploy.sh                     # серверный deploy/update скрипт
├── rc.example.sh                 # пример Selectel OpenStack rc-файла
├── systemd/
│   └── finder.service            # systemd unit template
├── .env.example                  # пример конфигурации без секретов
└── .gitignore
```

Файлы состояния создаются во время работы и не должны попадать в git:

```text
.env
rc_*.sh
ipwhitelist_safe_cidr.txt
good_ips.txt
banned_ips.txt
approved_vless_keys.txt
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
```

`TARGET_COUNT` означает общее количество рабочих ключей, а не количество новых IP на каждый запуск.

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
7. Когда новых кандидатов достаточно для свободных слотов, поиск останавливается и запускается VLESS-проверка.

## Слоты, approved и ban

`approved_vless_keys.txt` содержит рабочие ключи. Каждый IP в этом файле занимает один слот.

`banned_ips.txt` содержит IP, которые были отмечены как нерабочие. Такие IP:

- не считаются кандидатами;
- удаляются из `good_ips.txt`;
- при повторном выпадении сразу удаляются из Selectel.

`good_ips.txt` содержит новые подходящие IP-кандидаты, которые еще надо проверить.

## Автоматическая VLESS-проверка

Когда найдено достаточно новых кандидатов, бот запускает provisioning.

Настройки:

```env
PROVISION_ENABLED=true
PROVISION_ORIGIN_IP=YOUR_ORIGIN_IP
PROVISION_VLESS_TEMPLATE=vless://UUID@{WHITE_IP}:443?...#user
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
10. Отправляет ключ в Telegram с кнопками `Работает` / `Не работает`.

Команды, которые выполняются на сервере через cloud-init:

```bash
curl -fsSLO https://raw.githubusercontent.com/denpiligrim/3dp-manager/main/forwarding_install.sh
export ORIGIN_IP="$PROVISION_ORIGIN_IP"
sudo -E bash forwarding_install.sh
```

После ответа в Telegram временный сервер удаляется, если включено:

```env
PROVISION_DELETE_SERVER_AFTER_RESULT=true
```

Если нажать `Работает`:

- ключ сохраняется в `approved_vless_keys.txt`;
- IP занимает слот;
- бот переходит к следующему кандидату.

Если нажать `Не работает`:

- IP сохраняется в `banned_ips.txt`;
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
PROVISION_IMAGE_NAME=Ubuntu 24.04 LTS 64-bit
PROVISION_REQUIRE_LOCAL_DISK=true
```

Flavor выбирается автоматически: минимальный по vCPU, RAM и disk, с локальным диском.

Сеть выбирается автоматически: первая приватная сеть в регионе.

Если нужно зафиксировать ресурсы явно:

```env
PROVISION_IMAGE_ID=
PROVISION_FLAVOR_ID=
PROVISION_NETWORK_ID=
PROVISION_AVAILABILITY_ZONE=
```

Можно задать региональные override-переменные. В суффиксе региона `-` заменяется на `_`:

```env
PROVISION_IMAGE_ID_RU_1=
PROVISION_FLAVOR_ID_RU_1=
PROVISION_NETWORK_ID_RU_1=
PROVISION_AVAILABILITY_ZONE_RU_1=
```

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
- Не коммитьте `good_ips.txt`, `banned_ips.txt`, `approved_vless_keys.txt`.
- Если токен Telegram или пароль Selectel попал в переписку, скриншот или git, перевыпустите его.
- Храните OpenStack пароль в одинарных кавычках, если в нем есть `$`.
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
8. После получения VLESS-ключа проверить его вручную.
9. Нажать `Работает` или `Не работает`.
10. Повторять до заполнения `TARGET_COUNT` рабочих ключей.

## Будущий автодеплой

В проект добавлен GitHub Actions workflow:

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
