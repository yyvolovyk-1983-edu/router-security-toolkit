<div align="center">

# Router Security Toolkit

**Python-інструменти для авторизованого аудиту безпеки роутерів та домашніх мереж**

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://github.com/yyvolovyk-1983-edu/router-security-toolkit)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![No Dependencies](https://img.shields.io/badge/Dependencies-stdlib_only-brightgreen?style=for-the-badge)]()
[![Authorized Only](https://img.shields.io/badge/Use-Authorized_Only-red?style=for-the-badge)]()

</div>

---

## Інструменти

| Файл | Що робить |
|---|---|
| `http_probe.py` | Сканує 15+ вразливих HTTP-шляхів адмін-панелей |
| `backdoor_test.py` | Перевіряє відомі CVE-бекдори та UPnP |
| `upnp_ssl_test.py` | Аналізує UPnP-сервіси та SSL/TLS сертифікати |
| `default_creds_test.py` | Перевіряє дефолтні облікові дані адмін-панелей |

Залежності — лише стандартна бібліотека Python: `socket`, `ssl`, `urllib`.

---

## Використання

```bash
git clone https://github.com/yyvolovyk-1983-edu/router-security-toolkit
cd router-security-toolkit
pip install -r requirements.txt
```

### http_probe.py

```bash
python http_probe.py --host 192.168.1.1
python http_probe.py --host 192.168.1.1 --scheme https --timeout 5
```

### backdoor_test.py

```bash
python backdoor_test.py --host 192.168.1.1
```

| CVE | Опис | Порт |
|---|---|---|
| CVE-2015-0552 | Netcore/Netis UDP backdoor | 53413/UDP |
| UPnP SSDP | Виявлення UPnP-сервісів | 1900/UDP |

### upnp_ssl_test.py

```bash
python upnp_ssl_test.py --host 192.168.1.1
```

### default_creds_test.py

```bash
python default_creds_test.py --host 192.168.1.1
```

---

## Методологія аудиту (9 фаз)

```
Фаза 1   Збір інформації         — модель, прошивка, відкриті порти
Фаза 2   HTTP-розвідка           → http_probe.py
Фаза 3   Перевірка бекдорів      → backdoor_test.py
Фаза 4   UPnP / SSL аналіз       → upnp_ssl_test.py
Фаза 5   Дефолтні облікові дані  → default_creds_test.py
Фаза 6   Аналіз мережевого трафіку
Фаза 7   Перевірка конфігурації (NAT, port forwarding, MAC filtering)
Фаза 8   Класифікація вразливостей (Critical / High / Medium / Low)
Фаза 9   Звіт з рекомендаціями
```

---

## Реальний кейс

**Ціль:** Xiaomi Mi Router AX1800

| Показник | До аудиту | Після |
|---|---|---|
| Оцінка безпеки | **D** | **B+** |
| Знайдено вразливостей | — | **27** |
| Час на усунення | — | 48 годин |

---

> **Увага:** Інструменти призначені **виключно для авторизованого тестування**.
> Несанкціоноване використання є порушенням законодавства України (ст. 361 КК України).

---

<div align="center">

**Автор:** [Євген Воловик](https://github.com/yyvolovyk-1983-edu) · Харків, Україна
📧 y.y.volovyk@student.khai.edu · [LinkedIn](https://www.linkedin.com/in/yevhen-volovyk/)

</div>