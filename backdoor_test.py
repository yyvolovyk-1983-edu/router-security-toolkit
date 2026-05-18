"""
CVE Backdoor Tester для роутерів Netcore/Netis та UPnP discovery.

Перевіряє:
  - CVE-2015-0552: Netcore/Netis UDP backdoor (порт 53413)
  - UPnP SSDP discovery (порт 1900/UDP)

Використання:
    python backdoor_test.py --host 192.168.1.1
"""

import argparse
import socket


def test_netis_backdoor(host: str, port: int = 53413, timeout: int = 3) -> bool:
    """Перевіряє наявність CVE-2015-0552 backdoor (нейтральний probe)."""
    print(f"\n[*] CVE-2015-0552 — Netcore/Netis UDP backdoor ({host}:{port})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    probe = b"\x00\x00\x00\x08"  # мінімальний нейтральний Netcore UDP пакет

    try:
        sock.sendto(probe, (host, port))
        data, addr = sock.recvfrom(1024)
        print(f"  [!!!] BACKDOOR ВІДПОВІДАЄ! {len(data)} байт від {addr}")
        print(f"  [!!!] Hex: {data.hex()}")
        print("  [!!!] СТАТУС: КРИТИЧНО — CVE-2015-0552 підтверджено!")
        return True
    except socket.timeout:
        print("  [OK] Відповіді немає — backdoor відсутній або заблокований")
        return False
    except Exception as e:
        print(f"  [ERR] Помилка: {e}")
        return False
    finally:
        sock.close()


def test_upnp_ssdp(host: str, port: int = 1900, timeout: int = 5) -> list[str]:
    """UPnP SSDP unicast discovery."""
    print(f"\n[*] UPnP SSDP Discovery ({host}:{port})")

    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}:{port}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    responses = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    try:
        sock.sendto(ssdp_request, (host, port))
        while True:
            try:
                data, addr = sock.recvfrom(2048)
                decoded = data.decode(errors="replace")
                responses.append(decoded)
                print(f"  [+] UPnP відповідь від {addr[0]}:{addr[1]}")
                print(f"  {decoded[:200]}")
            except socket.timeout:
                break
    except Exception as e:
        print(f"  [ERR] {e}")
    finally:
        sock.close()

    if not responses:
        print("  [OK] UPnP вимкнено або заблоковано")

    return responses


def main():
    parser = argparse.ArgumentParser(description="CVE Backdoor Tester + UPnP Discovery")
    parser.add_argument("--host", required=True, help="IP роутера (напр. 192.168.1.1)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout в секундах (default: 3)")
    args = parser.parse_args()

    print(f"[*] Аудит backdoor/UPnP: {args.host}")
    print("=" * 60)

    backdoor_found = test_netis_backdoor(args.host, timeout=args.timeout)
    upnp_responses = test_upnp_ssdp(args.host, timeout=args.timeout + 2)

    print("\n" + "=" * 60)
    print("[*] ПІДСУМОК:")
    print(f"  CVE-2015-0552 backdoor: {'ЗНАЙДЕНО !!!' if backdoor_found else 'не знайдено'}")
    print(f"  UPnP сервіси:           {len(upnp_responses)} відповідей")


if __name__ == "__main__":
    main()
