import io
import subprocess


def _call_allowed(ctx, call) -> bool:
    return str(call.message.chat.id) == str(ctx.TELEGRAM_ALLOWED_CHAT_ID)


def register_telegram_handlers(ctx):
    bot = ctx.bot

    @bot.message_handler(commands=["start"])
    def cmd_start(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        try:
            result = ctx.start_finder(actor="telegram")
        except Exception as e:
            bot.reply_to(message, f"⚠️ Не могу запустить поиск: {e}")
            return

        if result.get("status") == "candidates_ready":
            bot.reply_to(
                message,
                f"{result['message']}\n\nЧтобы создать серверы и выдать ключи, нажми /create_servers.",
                reply_markup=ctx.create_servers_keyboard(),
            )
            return

        bot.reply_to(message, result["message"])

    @bot.message_handler(commands=["stop"])
    def cmd_stop(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        result = ctx.stop_finder(actor="telegram")
        bot.reply_to(message, result["message"])

    @bot.message_handler(commands=["status"])
    def cmd_status(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        try:
            networks = ctx.load_whitelist()
            whitelist_status = f"{len(networks)}"
        except Exception as e:
            networks = None
            whitelist_status = f"ошибка: {e}"

        approved = ctx.approved_count()
        current_target = ctx.target_count()
        slots_left = max(current_target - approved, 0)
        count = ctx.sync_good_ips(networks, exclude_approved=True)
        left_to_find = max(slots_left - count, 0)
        state = "работает" if ctx.running else "остановлен"
        fs = ctx.get_finder_state()

        with ctx.provisioning_lock:
            provision_state = "идет" if ctx.provisioning_running else "ожидает"

        tester_stats = ctx.format_vless_queue_stats()
        control = ctx.get_tester_control_state()
        tester_pause_text = (
            f"auto={'on' if control['full_auto_mode'] else 'off'}, "
            f"tasks={'paused' if control['testing_paused'] else 'running'}, "
            f"servers={'paused' if control['provisioning_paused'] else 'running'}"
        )

        bot.reply_to(
            message,
            f"📊 Статус: {state}\n"
            f"🔁 Попытка: {fs.get('current_attempt') or 0}\n"
            f"🌍 Текущий регион: {fs.get('current_region') or '-'}\n"
            f"🌐 Последний IP: {fs.get('last_ip') or '-'}\n"
            f"⚠️ Последняя ошибка: {fs.get('last_error') or '-'}\n"
            f"🕒 Запущен: {fs.get('started_at') or '-'}\n"
            f"✅ Принято ключей: {approved}/{current_target}\n"
            f"📦 Найдено кандидатов: {count}/{slots_left}\n"
            f"🔎 Осталось найти IP: {left_to_find}\n"
            f"🎯 Целей в файле: {whitelist_status}\n"
            f"🌍 Регионы: {ctx.format_regions()}\n"
            f"🧪 Создание серверов: {provision_state}\n"
            f"📲 Авто-тестер: {tester_stats}\n"
            f"⏯ Test control: {tester_pause_text}\n"
            f"🚫 Бан-лист: {len(ctx.load_banned_ips())}",
        )

    @bot.message_handler(commands=["test_status"])
    def cmd_test_status(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        stats = ctx.get_vless_queue_stats()
        recent = ctx.get_recent_vless_results(limit=8)
        api_state = "включен" if ctx.TESTER_API_ENABLED and ctx.TESTER_TOKEN else "выключен/нет токена"

        control = ctx.get_tester_control_state()
        lines = [
            "📲 Авто-тестер VLESS",
            f"API: {api_state}",
            f"Адрес: {ctx.TESTER_API_HOST}:{ctx.TESTER_API_PORT}",
            f"batch: {ctx.tester_batch_size()}",
            f"полный авто-режим: {'on' if control['full_auto_mode'] else 'off'}",
            f"выдача задач телефону: {'paused ⏸' if control['testing_paused'] else 'running ▶️'}",
            f"создание серверов: {'paused ⏸' if control['provisioning_paused'] else 'running ▶️'}",
            "",
            "Очередь:",
            f"queued: {stats.get('queued', 0)}",
            f"testing: {stats.get('testing', 0)}",
            f"provisioning: {stats.get('provisioning', 0)}",
            f"approved: {stats.get('approved', 0)}",
            f"ip_not_suitable: {stats.get('ip_not_suitable_total', 0)}",
            f"vless_failed: {stats.get('vless_failed', 0)}",
            f"exit_ip_mismatch: {stats.get('exit_ip_mismatch', 0)}",
            f"phone_failed: {stats.get('phone_failed', 0)}",
            f"provision_failed: {stats.get('provision_failed', 0)}",
            f"manual_banned: {stats.get('manual_banned', 0)}",
            f"rejected: {stats.get('rejected', 0)}",
            f"error: {stats.get('error', 0)}",
        ]

        if recent:
            lines.append("")
            lines.append("Последние результаты:")
            for item in recent:
                status = item.get("status") or "-"
                ip = item.get("ip") or "-"
                worker = item.get("worker") or "-"
                latency = item.get("latency_ms")
                latency_text = f" {latency}ms" if latency is not None else ""
                lines.append(f"{status} | {ip}{latency_text} | {worker}")

        bot.reply_to(message, "\n".join(lines))

    @bot.message_handler(commands=["test_stop", "pause_testing"])
    def cmd_test_stop(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        ctx.pause_all_testing()
        bot.reply_to(
            message,
            "⏸ Авто-тесты поставлены на паузу\n"
            "• телефонный worker останется online, но /next_tests будет возвращать пустой список\n"
            "• новые серверы создаваться не будут\n"
            "• уже выданная телефону задача может прислать результат",
        )

    @bot.message_handler(commands=["test_start", "resume_testing"])
    def cmd_test_start(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        ctx.resume_all_testing()
        bot.reply_to(
            message,
            "▶️ Авто-тесты возобновлены\n"
            "• /next_tests снова может выдавать задачи\n"
            "• /create_servers снова может создавать серверы",
        )

    @bot.message_handler(commands=["log"])
    def cmd_log(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        try:
            source = str(ctx.LOG_FILE)
            text = ""

            if ctx.LOG_FILE.exists():
                lines = ctx.LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]
                text = "\n".join(lines)
            else:
                source = "journalctl -u finder"
                result = subprocess.run(
                    ["journalctl", "-u", "finder", "-n", "200", "--no-pager"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=10,
                    check=False,
                )
                text = result.stdout or ""

            if not text.strip():
                bot.reply_to(message, f"📜 Логи пустые или недоступны: {source}")
                return

            data = io.BytesIO((ctx.redact_text(text) + "\n").encode("utf-8"))
            data.name = "finder_last_200_lines.log"
            bot.send_document(message.chat.id, data, caption=f"📜 Последние 200 строк логов ({source})")
        except Exception as e:
            bot.reply_to(message, f"⚠️ Не удалось отправить логи: {e}")

    @bot.message_handler(commands=["create_servers"])
    def cmd_create_servers(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        if ctx.is_provisioning_paused():
            bot.reply_to(message, "⏸ Создание серверов на паузе. Используй /test_start для возобновления.")
            return

        try:
            networks = ctx.load_whitelist()
        except Exception as e:
            bot.reply_to(message, f"⚠️ Не могу загрузить whitelist: {e}")
            return

        candidates = ctx.count_matching_good_ips(networks, exclude_approved=True)
        slots_left = ctx.remaining_slots()
        if candidates <= 0:
            bot.reply_to(message, "⚠️ Нет найденных IP-кандидатов для создания серверов")
            return

        bot.reply_to(message, f"🚀 Запускаю создание серверов и выдачу ключей для {min(candidates, slots_left)} IP")
        ctx.start_provisioning_if_needed(networks)

    @bot.message_handler(commands=["sync"])
    def cmd_sync(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        try:
            networks = ctx.load_whitelist()
        except Exception as e:
            bot.reply_to(message, f"⚠️ Не могу загрузить список целей: {e}")
            return

        count = ctx.sync_good_ips(networks, exclude_approved=True)
        bot.reply_to(
            message,
            "🔄 Синхронизация завершена.\n"
            f"✅ Принято ключей: {ctx.approved_count()}/{ctx.target_count()}\n"
            f"📦 Новых кандидатов: {count}/{ctx.remaining_slots()}",
        )

    @bot.message_handler(commands=["upload"])
    def cmd_upload(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        ctx.set_waiting_for_whitelist_file(True)
        bot.reply_to(
            message,
            "📎 Жду файл со списком IP/CIDR.\n"
            "Отправь его документом в этот чат. Для отмены: /cancel",
        )

    @bot.message_handler(commands=["cancel"])
    def cmd_cancel(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        if ctx.is_waiting_for_whitelist_file():
            ctx.set_waiting_for_whitelist_file(False)
            bot.reply_to(message, "✅ Ожидание файла отменено")
        else:
            bot.reply_to(message, "ℹ️ Сейчас я не жду файл")

    @bot.message_handler(commands=["regions"])
    def cmd_regions(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        bot.reply_to(message, ctx.regions_text(), reply_markup=ctx.region_keyboard())

    @bot.message_handler(commands=["help"])
    def cmd_help(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        bot.reply_to(message, ctx.help_text())

    @bot.callback_query_handler(func=lambda call: call.data and call.data.startswith("region:"))
    def callback_regions(call):
        if not _call_allowed(ctx, call):
            bot.answer_callback_query(call.id, "Access denied", show_alert=True)
            return

        action = call.data.split(":", 2)

        try:
            if call.data == "region:all":
                ctx.set_selected_regions(ctx.REGIONS)
                bot.answer_callback_query(call.id, "Выбраны все регионы")
            elif call.data == "region:done":
                bot.answer_callback_query(call.id, "Готово")
            elif len(action) == 3 and action[1] == "toggle":
                region = action[2]
                current = ctx.get_selected_regions()
                if region in current and len(current) == 1:
                    bot.answer_callback_query(call.id, "Нужен хотя бы один регион", show_alert=True)
                    return
                if region in current:
                    current.remove(region)
                else:
                    current.append(region)
                ctx.set_selected_regions(current)
                bot.answer_callback_query(call.id, f"Регионы: {ctx.format_regions()}")
            else:
                bot.answer_callback_query(call.id, "Неизвестное действие", show_alert=True)
                return

            bot.edit_message_text(
                ctx.regions_text(),
                chat_id=call.message.chat.id,
                message_id=call.message.message_id,
                reply_markup=ctx.region_keyboard(),
            )
        except Exception as e:
            bot.answer_callback_query(call.id, str(e), show_alert=True)

    @bot.callback_query_handler(func=lambda call: call.data == "provision:start")
    def callback_create_servers(call):
        if not _call_allowed(ctx, call):
            bot.answer_callback_query(call.id, "Access denied", show_alert=True)
            return

        try:
            networks = ctx.load_whitelist()
            candidates = ctx.count_matching_good_ips(networks, exclude_approved=True)
            slots_left = ctx.remaining_slots()
            if candidates <= 0:
                bot.answer_callback_query(call.id, "Нет найденных IP", show_alert=True)
                return
            bot.answer_callback_query(call.id, "Запускаю создание серверов")
            ctx.send(
                ctx.TELEGRAM_ALLOWED_CHAT_ID,
                f"🚀 Запускаю создание серверов и выдачу ключей для {min(candidates, slots_left)} IP",
            )
            ctx.start_provisioning_if_needed(networks)
        except Exception as e:
            bot.answer_callback_query(call.id, str(e), show_alert=True)

    @bot.callback_query_handler(func=lambda call: call.data and call.data.startswith("vless:"))
    def callback_vless_test(call):
        if not _call_allowed(ctx, call):
            bot.answer_callback_query(call.id, "Access denied", show_alert=True)
            return

        parts = call.data.split(":", 2)
        if len(parts) != 3:
            bot.answer_callback_query(call.id, "Некорректная кнопка", show_alert=True)
            return

        _, result, token = parts
        if result not in {"ok", "bad"}:
            bot.answer_callback_query(call.id, "Некорректный результат", show_alert=True)
            return

        with ctx.provisioning_lock:
            pending = ctx.pending_vless_tests.get(token)

        if not pending:
            bot.answer_callback_query(call.id, "Эта проверка уже закрыта", show_alert=True)
            return

        pending.result = result
        pending.event.set()

        if result == "ok":
            bot.answer_callback_query(call.id, "Отмечено: работает")
        else:
            bot.answer_callback_query(call.id, "Отмечено: не работает")

    @bot.message_handler(content_types=["document"])
    def handle_whitelist_document(message):
        if not ctx.allowed(message):
            bot.reply_to(message, "⛔ Access denied")
            return

        if not ctx.is_waiting_for_whitelist_file():
            bot.reply_to(message, "ℹ️ Файл не обработан. Для загрузки списка IP/CIDR сначала отправь /upload")
            return

        document = message.document
        file_name = document.file_name or "file"

        if document.file_size and document.file_size > ctx.WHITELIST_MAX_BYTES:
            bot.reply_to(message, f"⚠️ Файл слишком большой. Максимум: {ctx.WHITELIST_MAX_BYTES} bytes")
            return

        try:
            file_info = bot.get_file(document.file_id)
            data = bot.download_file(file_info.file_path)
            count = ctx.save_whitelist_from_bytes(data)
        except Exception as e:
            bot.reply_to(message, f"⚠️ Не удалось загрузить список из файла {file_name}: {e}")
            return

        ctx.set_waiting_for_whitelist_file(False)
        suffix = "\nПоиск уже идет — новый список будет подхвачен автоматически." if ctx.running else ""
        bot.reply_to(
            message,
            f"✅ Список целей обновлен из файла {file_name}\n"
            f"🎯 Загружено IP/CIDR: {count}{suffix}",
        )
