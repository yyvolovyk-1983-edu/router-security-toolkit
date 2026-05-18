# Router Security Toolkit

> Набір Python-інструментів для авторизованого аудиту безпеки роутерів та домашніх мереж.

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Security](https://img.shields.io/badge/Use-Authorized_Only-red?style=flat)]()

---

## ⚠️ Відповідальне використання

Ці інструменти призначені **виключно для авторизованого тестування** — власних пристроїв або за письмовим дозволом власника мережі. Несанкціоноване тестування чужих мереж є протизаконним.

---

## Інструменти

### `http_probe.py` — HTTP Path Scanner
Перевіряє типові вразливі HTTP-шляхи на роутерах (Boa HTTPd, Netis, LuCI, TP-Link).

```bash
python http_probe.py --host 192.168.1.1 --scheme http
```

Перевіряє шляхи: `/cgi-bin/`, `/admin/`, `/goform/`, `/boaform/`, `/setup.cgi`, та інші.

---

### `backdoor_test.py` — CVE Backdoor Tester
Перевіряє наявність відомих backdoor-вразливостей:
- **CVE-2015-0552** — Netcore/Netis UDP backdoor (порт 53413)
- **UPnP SSDP** discovery (порт 1900/UDP)

```bash
python backdoor_test.py --host 192.168.1.1
```

---

### `upnp_ssl_test.py` — UPnP & SSL Analyzer
- UPnP SSDP multicast discovery
- SSL/TLS certificate details та версія шифрування

```bash
python upnp_ssl_test.py --host 192.168.1.1
```

---

### `default_creds_test.py` — Default Credentials Checker
Перевірка типових паролів адмін-панелей роутерів.

```bash
python default_creds_test.py --host 192.168.1.1 --port 80
```

---

## Встановлення

```bash
git clone https://github.com/yyvolovyk-1983-edu/router-security-toolkit
cd router-security-toolkit
pip install -r requirements.txt
```

Залежності: тільки стандартна бібліотека Python (socket, ssl, urllib) — зовнішніх пакетів не потрібно.

---

## Методологія аудиту (9 фаз)

```
Фаза 0: Збір інформації (IP, ISP, PTR, whois)
Фаза 1: Мережева топологія (ARP, host discovery, port scan)
Фаза 2: Аудит роутера (HTTP paths, CVE, UPnP, SSL)
Фаза 3: Wi-Fi аналіз (SSID, шифрування, WPS)
Фаза 4: Аудит хоста Windows (netstat, autoruns, служби)
Фаза 5: Браузер (розширення, history)
Фаза 6: Active Directory / DNS
Фаза 7: Логи безпеки (Event Log, Defender)
Фаза 8: Фінальний звіт + план усунення
```

---

## Результати реального аудиту

Застосовано для аудиту домашньої мережі з роутером **Xiaomi Mi Router AX1800**:
- Знайдено і закрито **27 знахідок** за 48 годин
- Загальна оцінка безпеки: **D → B+**
- Усунуто: застарілий роутер з backdoor, налаштовано WPA3, VPN, MAC whitelist

---

## Структура проекту

```
router-security-toolkit/
├── http_probe.py           # HTTP path scanner
├── backdoor_test.py        # CVE backdoor tester
├── upnp_ssl_test.py        # UPnP & SSL analyzer
├── default_creds_test.py   # Default credentials checker
├── requirements.txt
└── docs/
    └── audit-methodology.md    # Детальна методологія аудиту
```

---

## Автор

**Євген Воловик** — Security Researcher, ХНУА «ХАІ»

[![GitHub](https://img.shields.io/badge/GitHub-yyvolovyk--1983--edu-181717?style=flat&logo=github)](https://github.com/yyvolovyk-1983-edu)
