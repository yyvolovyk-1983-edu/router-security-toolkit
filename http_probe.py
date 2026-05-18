"""
HTTP Path Scanner для аудиту роутерів.
Перевіряє типові вразливі шляхи (Boa HTTPd, Netis, LuCI, TP-Link).

Використання:
    python http_probe.py --host 192.168.1.1
    python http_probe.py --host 192.168.1.1 --scheme https --timeout 5
"""

import argparse
import ssl
import urllib.error
import urllib.request

VULNERABLE_PATHS = [
    "/",
    "/cgi-bin/",
    "/admin/",
    "/setup.cgi",
    "/login.cgi",
    "/apply.cgi",
    "/status.cgi",
    "/userRpm/",
    "/goform/",
    "/boaform/",
    "/boaform/admin/formLogin",
    "/cgi-bin/upload.cgi",
    "/getpage.gch",
    "/status",
    "/api/",
    "/cgi-bin/luci/",
]


def build_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def probe_router(host: str, scheme: str = "http", timeout: int = 3) -> list[tuple[int, str]]:
    results = []
    ctx = build_ssl_context() if scheme == "https" else None
    headers = {"User-Agent": "Mozilla/5.0 (security-audit)"}

    for path in VULNERABLE_PATHS:
        url = f"{scheme}://{host}{path}"
        try:
            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
            results.append((resp.status, url))
        except urllib.error.HTTPError as e:
            results.append((e.code, url))
        except Exception:
            pass

    return results


def main():
    parser = argparse.ArgumentParser(description="HTTP Path Scanner для аудиту роутерів")
    parser.add_argument("--host", required=True, help="IP або hostname роутера (напр. 192.168.1.1)")
    parser.add_argument("--scheme", default="http", choices=["http", "https"], help="Протокол (default: http)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout в секундах (default: 3)")
    args = parser.parse_args()

    print(f"[*] Сканування HTTP шляхів на {args.scheme}://{args.host}")
    print("-" * 60)

    results = probe_router(args.host, args.scheme, args.timeout)

    if not results:
        print("[!] Відповідей немає — хост недоступний або всі шляхи закриті")
        return

    print(f"[+] Знайдено відповідей: {len(results)}")
    for status, url in results:
        marker = "[!] УВАГА" if status < 400 else "[ ]"
        print(f"  {marker}  {status}  {url}")


if __name__ == "__main__":
    main()
