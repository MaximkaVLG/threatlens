"""Built-in threat explanations — works without any AI provider.

Generates human-readable explanations based on analysis findings.
No API keys, no internet, no external dependencies.
"""

from dataclasses import dataclass

# Explanation templates for each threat category
# Format: (condition_keywords, title_ru, explanation_ru, title_en, explanation_en)
THREAT_EXPLANATIONS = {
    "password_theft": {
        "title_ru": "Кража паролей",
        "title_en": "Password Theft",
        "explain_ru": (
            "Этот файл пытается получить доступ к сохранённым паролям в вашем браузере.\n"
            "Он ищет базы данных паролей Chrome, Firefox или других браузеров.\n\n"
            "Если вы уже запускали этот файл — немедленно смените ВСЕ пароли,\n"
            "особенно от почты, банков и социальных сетей."
        ),
        "explain_en": (
            "This file attempts to access saved passwords in your browser.\n"
            "It searches for Chrome, Firefox, or other browser password databases.\n\n"
            "If you have already run this file — change ALL your passwords immediately,\n"
            "especially email, banking, and social media accounts."
        ),
    },
    "injection": {
        "title_ru": "Внедрение кода",
        "title_en": "Code Injection",
        "explain_ru": (
            "Этот файл может внедрять свой код в другие запущенные программы.\n"
            "Это позволяет ему скрываться от антивирусов и получать доступ\n"
            "к данным других приложений.\n\n"
            "Типичное поведение троянов и RAT (средств удалённого доступа)."
        ),
        "explain_en": (
            "This file can inject its code into other running programs.\n"
            "This allows it to hide from antivirus software and access\n"
            "data from other applications.\n\n"
            "Typical behavior of trojans and RATs (Remote Access Tools)."
        ),
    },
    "keylogger": {
        "title_ru": "Клавиатурный шпион",
        "title_en": "Keylogger",
        "explain_ru": (
            "Этот файл перехватывает нажатия клавиш на клавиатуре.\n"
            "Всё что вы набираете — пароли, сообщения, данные карт —\n"
            "может записываться и отправляться злоумышленнику.\n\n"
            "Если запускали — смените все пароли С ДРУГОГО устройства."
        ),
        "explain_en": (
            "This file intercepts keyboard keystrokes.\n"
            "Everything you type — passwords, messages, card details —\n"
            "may be recorded and sent to an attacker.\n\n"
            "If you ran it — change all passwords FROM A DIFFERENT device."
        ),
    },
    "crypto": {
        "title_ru": "Криптовалюта / Шифровальщик",
        "title_en": "Cryptocurrency / Ransomware",
        "explain_ru": (
            "Этот файл связан с криптовалютами. Возможные варианты:\n"
            "- Майнер: тайно использует ваш компьютер для добычи криптовалюты\n"
            "- Стилер кошельков: крадёт ваши криптокошельки\n"
            "- Шифровальщик: шифрует ваши файлы и требует выкуп\n\n"
            "Не запускайте этот файл. Если запустили — отключите интернет."
        ),
        "explain_en": (
            "This file is related to cryptocurrency. Possible scenarios:\n"
            "- Miner: secretly uses your computer to mine cryptocurrency\n"
            "- Wallet stealer: steals your crypto wallets\n"
            "- Ransomware: encrypts your files and demands payment\n\n"
            "Do not run this file. If you did — disconnect from the internet."
        ),
    },
    "data_exfiltration": {
        "title_ru": "Отправка данных злоумышленнику",
        "title_en": "Data Exfiltration",
        "explain_ru": (
            "Этот файл отправляет собранные данные на внешний сервер.\n"
            "Каналы отправки: Telegram-бот, Discord-вебхук, email или FTP.\n\n"
            "Ваши пароли, файлы и личные данные могут быть уже отправлены.\n"
            "Смените пароли и проверьте историю активности в аккаунтах."
        ),
        "explain_en": (
            "This file sends collected data to an external server.\n"
            "Exfiltration channels: Telegram bot, Discord webhook, email, or FTP.\n\n"
            "Your passwords, files, and personal data may have already been sent.\n"
            "Change your passwords and check account activity history."
        ),
    },
    "persistence": {
        "title_ru": "Закрепление в системе",
        "title_en": "System Persistence",
        "explain_ru": (
            "Этот файл пытается закрепиться в вашей системе —\n"
            "добавить себя в автозагрузку, реестр или планировщик задач.\n"
            "Это значит он будет запускаться каждый раз при включении компьютера.\n\n"
            "Проверьте автозагрузку (Win+R → msconfig → Автозагрузка)."
        ),
        "explain_en": (
            "This file tries to persist in your system —\n"
            "adding itself to startup, registry, or task scheduler.\n"
            "This means it will run every time you turn on your computer.\n\n"
            "Check startup items (Win+R → msconfig → Startup)."
        ),
    },
    "obfuscation": {
        "title_ru": "Обфускация (маскировка)",
        "title_en": "Obfuscation",
        "explain_ru": (
            "Код этого файла намеренно запутан или зашифрован.\n"
            "Легитимные программы обычно не скрывают свой код.\n"
            "Обфускация используется чтобы затруднить анализ антивирусами.\n\n"
            "Это не гарантирует вредоносность, но это серьёзный красный флаг."
        ),
        "explain_en": (
            "This file's code is intentionally obfuscated or encrypted.\n"
            "Legitimate programs usually don't hide their code.\n"
            "Obfuscation is used to evade antivirus analysis.\n\n"
            "This doesn't guarantee maliciousness, but it's a serious red flag."
        ),
    },
    "network": {
        "title_ru": "Сетевая активность",
        "title_en": "Network Activity",
        "explain_ru": (
            "Этот файл устанавливает соединения с внешними серверами.\n"
            "Он может скачивать дополнительные вредоносные компоненты,\n"
            "отправлять ваши данные или получать команды от злоумышленника.\n\n"
            "Проверьте адреса в разделе 'Findings' — знакомы ли вам эти серверы?"
        ),
        "explain_en": (
            "This file establishes connections to external servers.\n"
            "It may download additional malicious components,\n"
            "send your data, or receive commands from an attacker.\n\n"
            "Check the addresses in 'Findings' — do you recognize these servers?"
        ),
    },
    "evasion": {
        "title_ru": "Обход защиты",
        "title_en": "Defense Evasion",
        "explain_ru": (
            "Этот файл проверяет, не запущен ли он в антивирусной песочнице\n"
            "или виртуальной машине. Если да — он скрывает своё поведение.\n"
            "Это типичная тактика продвинутых вредоносных программ.\n\n"
            "Файл целенаправленно пытается избежать обнаружения."
        ),
        "explain_en": (
            "This file checks if it's running in an antivirus sandbox\n"
            "or virtual machine. If so, it hides its malicious behavior.\n"
            "This is a typical tactic of advanced malware.\n\n"
            "The file deliberately tries to avoid detection."
        ),
    },
    "hooking": {
        "title_ru": "Перехват системных функций",
        "title_en": "System Hooking",
        "explain_ru": (
            "Этот файл перехватывает системные функции Windows.\n"
            "Это позволяет ему контролировать поведение других программ,\n"
            "перехватывать ввод с клавиатуры или скрывать своё присутствие."
        ),
        "explain_en": (
            "This file hooks into Windows system functions.\n"
            "This allows it to control other programs' behavior,\n"
            "intercept keyboard input, or hide its presence."
        ),
    },
    "privilege_escalation": {
        "title_ru": "Повышение привилегий",
        "title_en": "Privilege Escalation",
        "explain_ru": (
            "Этот файл пытается получить права администратора.\n"
            "С повышенными правами он может изменять системные файлы,\n"
            "устанавливать драйверы и полностью контролировать компьютер."
        ),
        "explain_en": (
            "This file attempts to gain administrator privileges.\n"
            "With elevated rights, it can modify system files,\n"
            "install drivers, and fully control the computer."
        ),
    },
}

# Combined threat explanations for common malware types
COMBINED_EXPLANATIONS = {
    "stealer": {
        "categories": {"password_theft", "data_exfiltration"},
        "title_ru": "Стилер (похититель данных)",
        "title_en": "Stealer (Data Thief)",
        "explain_ru": (
            "Этот файл — стилер. Он крадёт данные с вашего компьютера и отправляет злоумышленнику.\n\n"
            "Что он крадёт:\n"
            "- Сохранённые пароли из браузеров\n"
            "- Cookies (доступ к вашим аккаунтам без пароля)\n"
            "- Данные криптокошельков\n"
            "- Файлы с рабочего стола и документов\n\n"
            "Что делать:\n"
            "1. Удалить этот файл\n"
            "2. Сменить ВСЕ пароли с другого устройства\n"
            "3. Включить двухфакторную аутентификацию везде\n"
            "4. Проверить активные сессии в аккаунтах"
        ),
        "explain_en": (
            "This file is a stealer. It steals data from your computer and sends it to an attacker.\n\n"
            "What it steals:\n"
            "- Saved browser passwords\n"
            "- Cookies (access to your accounts without password)\n"
            "- Crypto wallet data\n"
            "- Files from desktop and documents\n\n"
            "What to do:\n"
            "1. Delete this file\n"
            "2. Change ALL passwords from a different device\n"
            "3. Enable two-factor authentication everywhere\n"
            "4. Check active sessions in your accounts"
        ),
    },
    "rat": {
        "categories": {"injection", "network", "persistence"},
        "title_ru": "RAT (троян удалённого доступа)",
        "title_en": "RAT (Remote Access Trojan)",
        "explain_ru": (
            "Этот файл — RAT (троян удалённого доступа).\n"
            "Он даёт злоумышленнику полный контроль над вашим компьютером.\n\n"
            "Что может делать злоумышленник:\n"
            "- Видеть ваш экран\n"
            "- Управлять мышью и клавиатурой\n"
            "- Читать и изменять файлы\n"
            "- Включать камеру и микрофон\n"
            "- Скачивать и запускать другие программы\n\n"
            "Что делать:\n"
            "1. Отключить интернет НЕМЕДЛЕННО\n"
            "2. Удалить файл\n"
            "3. Запустить полное сканирование антивирусом\n"
            "4. Сменить все пароли с другого устройства"
        ),
        "explain_en": (
            "This file is a RAT (Remote Access Trojan).\n"
            "It gives the attacker full control over your computer.\n\n"
            "What the attacker can do:\n"
            "- See your screen\n"
            "- Control mouse and keyboard\n"
            "- Read and modify files\n"
            "- Turn on camera and microphone\n"
            "- Download and run other programs\n\n"
            "What to do:\n"
            "1. Disconnect from internet IMMEDIATELY\n"
            "2. Delete the file\n"
            "3. Run full antivirus scan\n"
            "4. Change all passwords from a different device"
        ),
    },
}


def generate_explanation(categories: dict, lang: str = "ru") -> str:
    """Generate human-readable explanation from threat categories.

    Args:
        categories: dict of {category_name: score} from threat_scorer
        lang: 'ru' for Russian, 'en' for English

    Returns:
        Multi-line explanation string
    """
    if not categories:
        if lang == "ru":
            return "Подозрительных признаков не обнаружено. Файл выглядит безопасным."
        return "No suspicious indicators found. The file appears safe."

    active_cats = set(categories.keys())
    parts = []

    # Check for combined explanations first (stealer, RAT)
    for combo_name, combo in COMBINED_EXPLANATIONS.items():
        if combo["categories"].issubset(active_cats):
            title = combo[f"title_{lang}"]
            explain = combo[f"explain_{lang}"]
            return f"--- {title} ---\n\n{explain}"

    # Individual category explanations
    # Sort by score (most dangerous first)
    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)

    for cat_name, score in sorted_cats:
        if cat_name in THREAT_EXPLANATIONS:
            tmpl = THREAT_EXPLANATIONS[cat_name]
            title = tmpl[f"title_{lang}"]
            explain = tmpl[f"explain_{lang}"]
            parts.append(f"[{title}]\n{explain}")

    if not parts:
        if lang == "ru":
            return "Обнаружены подозрительные признаки, но точный тип угрозы не определён.\nРекомендуем не запускать этот файл."
        return "Suspicious indicators found, but exact threat type is undetermined.\nWe recommend not running this file."

    return "\n\n".join(parts)
