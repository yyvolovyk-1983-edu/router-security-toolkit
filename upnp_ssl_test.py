"""
UPnP SSDP Multicast Discovery + SSL/TLS Certificate Analyzer.

Використання:
    python upnp_ssl_test.py --host 192.168.1.1
    python upnp_ssl_test.py --host 192.168.1.1 --ssl-port 443
"""

import argparse
import socket
import ssl


def upnp_multicast_discovery(timeout: int = 5) -> list[tuple[str, str]]:
    """UPnP SSDP multicast discovery в локальній мережі."""
    print("\n[*] UPnP SSDP Multicast Discovery (239.255.255.250:1900)")

    ssdp = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(timeout)

    responses = []
    try:
        sock.sendto(ssdp, ("239.255.255.250", 1900))
        print("  [*] M-SEARCH надіслано, чекаємо відповідей...")
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                decoded = data.decode(errors="replace")
                responses.append((f"{addr[0]}:{addr[1]}", decoded))
                print(f"  [+] Відповідь від {addr[0]}:{addr[1]}")
                for line in decoded.splitlines()[:5]:
                    if line.strip():
                        print(f"      {line}")
            except socket.timeout:
                break
    except Exception as e:
        print(f"  [ERR] {e}")
    finally:
        sock.close()

    if not responses:
        print("  [OK] UPnP пристроїв не знайдено (вимкнено або заблоковано)")

    return responses


def analyze_ssl(host: str, port: int = 443, timeout: int = 5) -> dict | None:
    """Аналізує SSL/TLS сертифікат та шифрування."""
    print(f"\n[*] SSL/TLS Аналіз: {host}:{port}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result = {
                    "tls_version": version,
                    "cipher_name": cipher[0] if cipher else "невідомо",
                    "cipher_bits": cipher[2] if cipher else 0,
                    "cert": cert,
                }

                print(f"  TLS версія:    {result['tls_version']}")
                print(f"  Шифр:         {result['cipher_name']} ({result['cipher_bits']} bit)")

                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    print(f"  CN (суб'єкт): {subject.get('commonName', 'н/д')}")
                    print(f"  Видавець:     {issuer.get('commonName', 'н/д')}")
                    print(f"  Дійсний до:   {cert.get('notAfter', 'н/д')}")

                    if result["tls_version"] in ("TLSv1", "TLSv1.1", "SSLv3"):
                        print(f"  [!!!] УВАГА: застаріла версія TLS ({result['tls_version']})")
                    if result["cipher_bits"] and result["cipher_bits"] < 128:
                        print(f"  [!!!] УВАГА: слабке шифрування ({result['cipher_bits']} bit)")
                else:
                    print("  [!] Сертифікат не отримано (самопідписаний або помилка)")

                return result

    except ConnectionRefusedError:
        print(f"  [OK] Порт {port} закрито — HTTPS не доступний")
    except Exception as e:
        print(f"  [ERR] {e}")

    return None


def main():
    parser = argparse.ArgumentParser(description="UPnP Discovery + SSL/TLS Analyzer")
    parser.add_argument("--host", required=True, help="IP роутера (напр. 192.168.1.1)")
    parser.add_argument("--ssl-port", type=int, default=443, help="Порт HTTPS (default: 443)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout в секундах (default: 5)")
    parser.add_argument("--no-multicast", action="store_true", help="Пропустити multicast discovery")
    args = parser.parse_args()

    print(f"[*] UPnP + SSL аудит: {args.host}")
    print("=" * 60)

    upnp_devices = []
    if not args.no_multicast:
        upnp_devices = upnp_multicast_discovery(timeout=args.timeout)

    ssl_result = analyze_ssl(args.host, args.ssl_port, args.timeout)

    print("\n" + "=" * 60)
    print("[*] ПІДСУМОК:")
    print(f"  UPnP пристроїв:  {len(upnp_devices)}")
    print(f"  HTTPS:           {'доступний' if ssl_result else 'недоступний'}")
    if ssl_result:
        weak = ssl_result["tls_version"] in ("TLSv1", "TLSv1.1") or (ssl_result["cipher_bits"] or 128) < 128
        print(f"  TLS безпека:     {'[!!!] СЛАБКА' if weak else 'OK'}")


if __name__ == "__main__":
    main()
