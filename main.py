import asyncio
import base64
import ipaddress
import json
import re
import subprocess
import time
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse

import aiohttp
from aiohttp_socks import ProxyConnector

# Расширенный список репозиториев: VLESS-PO-GRIBI + rjsxrd + профильные VLESS-агрегаторы
SOURCES = [
    # 1. Репозиторий VLESS-PO-GRIBI (основные подписки)
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/5.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/6.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/8.txt",
    # 2. Репозиторий rjsxrd (обход белых списков РФ + проверенные VLESS)
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/vless.txt",
    # 3. Дополнительные крупные агрегаторы VLESS-конфигов
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
]

TCP_CONCURRENCY = 200
TCP_TIMEOUT = 2.0
MAX_CANDIDATES_FOR_XRAY = 350
XRAY_BATCH_SIZE = 50
MAX_PING_MS = 4000
STRICT_US_ONLY = False  # False: США на 1 месте + Великобритания/Европа следом

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
VALID_ALPNS = {"h2", "http/1.1", "h3"}
SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

CF_NETS = [
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
]

RU_WHITELIST_MARKERS = (
    ".ru", "ozon", "yandex", "vk.com", "userapi", "wb.ru",
    "wildberries", "mail.ru", "kaspersky", "sber", "tinkoff", "gosuslugi"
)


def is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CF_NETS)
    except Exception:
        return False


def safe_b64decode(data: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", data)
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def is_valid_reality_pbk(pbk: str) -> bool:
    if not pbk or len(pbk) not in (43, 44):
        return False
    cleaned = pbk.replace("-", "+").replace("_", "/")
    padding = len(cleaned) % 4
    if padding:
        cleaned += "=" * (4 - padding)
    try:
        return len(base64.b64decode(cleaned)) == 32
    except Exception:
        return False


def is_valid_domain_or_ip(val: str) -> bool:
    if not val or len(val) > 253 or " " in val:
        return False
    return bool(re.match(r"^[A-Za-z0-9.-]+$", val))


def parse_stream_settings(params: dict, default_host: str) -> dict | None:
    net = params.get("type", ["tcp"])[0].lower()
    security = params.get("security", ["none"])[0].lower()

    if params.get("allowInsecure", ["0"])[0] in ("1", "true") or params.get("insecure", ["0"])[0] in ("1", "true"):
        return None

    stream = {"network": net, "security": security}

    if net == "tcp":
        header_type = params.get("headerType", ["none"])[0]
        if header_type == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [params.get("path", ["/"])[0]],
                        "headers": {"Host": [params.get("host", [default_host])[0]]},
                    },
                }
            }
        else:
            stream["tcpSettings"] = {"header": {"type": "none"}}
    elif net == "ws":
        if security == "reality":
            return None
        stream["wsSettings"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": params.get("host", [default_host])[0]},
        }
    elif net == "grpc":
        svc = params.get("serviceName", [""])[0]
        if not re.match(r"^[A-Za-z0-9_./-]*$", svc):
            return None
        stream["grpcSettings"] = {
            "serviceName": svc,
            "multiMode": params.get("mode", ["gun"])[0] == "multi",
        }
    elif net == "httpupgrade":
        if security == "reality":
            return None
        stream["httpupgradeSettings"] = {
            "path": params.get("path", ["/"])[0],
            "host": params.get("host", [default_host])[0],
        }
    else:
        return None

    if security == "tls":
        sni = params.get("sni", [params.get("host", [default_host])[0]])[0].strip()
        if not is_valid_domain_or_ip(sni):
            return None
        fp = params.get("fp", ["chrome"])[0].lower()
        tls_cfg = {
            "serverName": sni,
            "fingerprint": fp if fp in VALID_FPS else "chrome",
        }
        if "alpn" in params and params["alpn"][0]:
            alpns = [a.strip() for a in params["alpn"][0].split(",") if a.strip() in VALID_ALPNS]
            if alpns:
                tls_cfg["alpn"] = alpns
        stream["tlsSettings"] = tls_cfg

    elif security == "reality":
        pbk = params.get("pbk", [""])[0].strip()
        sid = params.get("sid", [""])[0].strip()
        sni = params.get("sni", [""])[0].strip()
        if not is_valid_domain_or_ip(sni) or not is_valid_reality_pbk(pbk):
            return None
        if sid and (len(sid) > 16 or not HEX_RE.match(sid)):
            return None
        fp = params.get("fp", ["firefox"])[0].lower()
        spx = params.get("spx", ["/"])[0].strip()
        if not spx.startswith("/"):
            spx = "/"
        stream["realitySettings"] = {
            "fingerprint": fp if fp in VALID_FPS else "firefox",
            "publicKey": pbk,
            "serverName": sni,
            "shortId": sid,
            "show": False,
            "spiderX": spx,
        }
    elif security != "none":
        return None

    return stream


def parse_proxy_uri(uri: str, source_priority: int = 1) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vless://"):
            parsed = urlparse(uri)
            uuid = unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            if not host or not is_valid_domain_or_ip(host) or not port or not (1 <= int(port) <= 65535) or not UUID_RE.match(uuid):
                return None
            params = parse_qs(parsed.query)
            stream = parse_stream_settings(params, host)
            if not stream:
                return None
            flow = params.get("flow", [""])[0]
            if flow:
                if flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                    return None
                if stream["network"] != "tcp" or stream["security"] not in ("tls", "reality"):
                    return None
            sni = params.get("sni", [""])[0].lower()
            is_reality = stream["security"] == "reality"
            has_ru_whitelist_sni = is_reality and any(m in sni for m in RU_WHITELIST_MARKERS)

            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{
                            "encryption": "none",
                            "flow": flow,
                            "id": uuid,
                            "level": 8,
                            "security": "auto",
                        }],
                    }]
                },
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "vless", "host": host, "port": int(port),
                "is_reality": is_reality, "whitelist_sni": has_ru_whitelist_sni,
                "source_prio": source_priority,
                "key": f"vless:{host}:{port}:{uuid}", "remark": unquote(parsed.fragment),
                "outbound": outbound,
            }

        elif uri.startswith("trojan://"):
            parsed = urlparse(uri)
            password = unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            if not host or not is_valid_domain_or_ip(host) or not port or not (1 <= int(port) <= 65535) or not password:
                return None
            params = parse_qs(parsed.query)
            if "security" not in params:
                params["security"] = ["tls"]
            stream = parse_stream_settings(params, host)
            if not stream:
                return None
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": int(port), "password": password, "level": 8}]},
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "trojan", "host": host, "port": int(port),
                "is_reality": stream["security"] == "reality", "whitelist_sni": False,
                "source_prio": source_priority,
                "key": f"trojan:{host}:{port}:{password}", "remark": unquote(parsed.fragment),
                "outbound": outbound,
            }
    except Exception:
        return None
    return None


def rename_uri(node: dict, new_remark: str) -> str:
    base_uri = node["uri"].split("#")[0]
    if node["proto"] in ("vless", "trojan"):
        parsed = urlparse(base_uri)
        q = parse_qs(parsed.query, keep_blank_values=True)
        q.pop("allowInsecure", None)
        q.pop("insecure", None)
        clean_query = urlencode(q, doseq=True)
        base_uri = urlunparse(parsed._replace(query=clean_query, fragment=""))
    return f"{base_uri}#{quote(new_remark)}"


async def fetch_sources() -> list[dict]:
    nodes = {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        for idx, url in enumerate(SOURCES):
            # Приоритет 0 для VLESS-PO-GRIBI и rjsxrd, 1 для остальных глобальных баз
            src_prio = 0 if ("VLESS-PO-GRIBI" in url or "rjsxrd" in url) else 1
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        raw_bytes = await resp.read()
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        if "://" not in text[:300]:
                            text = safe_b64decode(text)
                        if text:
                            lines = text.splitlines()
                            added = 0
                            for line in lines:
                                line = line.strip()
                                if line.startswith(("vless://", "trojan://")):
                                    parsed = parse_proxy_uri(line, src_prio)
                                    if parsed and parsed["key"] not in nodes:
                                        nodes[parsed["key"]] = parsed
                                        added += 1
                            print(f"[+] Источник ({added} новых узлов): {url}")
            except Exception as e:
                print(f"[-] Пропущен источник {url}: {e}")

    print(f"[*] Всего уникальных валидных конфигов после парсинга: {len(nodes)}")
    return list(nodes.values())


async def check_tcp(node: dict, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(node["host"], node["port"])
            reader, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
            peer = writer.get_extra_info("peername")
            node["ip"] = peer[0] if peer else node["host"]
            writer.close()
            await writer.wait_closed()
            node["tcp_ms"] = int((time.monotonic() - t0) * 1000)
            return node
        except Exception:
            return None


def prioritize_candidates(nodes: list[dict]) -> list[dict]:
    # Отсеиваем фейковые Anycast IP Cloudflare, но НЕ отсеиваем серверы по входному GeoIP,
    # так как лучшие серверы для РФ часто имеют каскадный вход или RIPE-регистрацию хостера в РФ!
    filtered = [n for n in nodes if not is_cloudflare_ip(n.get("ip", ""))]
    print(f"[*] После отсева пустышек Cloudflare осталось: {len(filtered)} серверов")

    us_keywords = ("US", "USA", "🇺🇸", "United States", "GBR", "🇬🇧", "NL", "🇳🇱", "DE", "🇩🇪")
    for n in filtered:
        has_good_tag = any(k.lower() in n["remark"].lower() for k in us_keywords)
        # Сортировка кандидатов:
        # 1) Reality с доменом из белых списков РФ (ozon.ru, vk.com и т.д.)
        # 2) Проверенные репозитории (VLESS-PO-GRIBI / rjsxrd)
        # 3) Протокол VLESS Reality
        # 4) Метка США/Европы и минимальный пинг
        n["sort_key"] = (
            0 if n["whitelist_sni"] else 1,
            n["source_prio"],
            0 if n["is_reality"] else 1,
            0 if has_good_tag else 1,
            n["tcp_ms"],
        )

    filtered.sort(key=lambda x: x["sort_key"])
    return filtered[:MAX_CANDIDATES_FOR_XRAY]


async def get_exit_country(session: aiohttp.ClientSession) -> str | None:
    # Способ 1: Прямой IP Cloudflare 1.1.1.1 (не режется WAF, в отличие от www.cloudflare.com)
    try:
        async with session.get("https://1.1.1.1/cdn-cgi/trace", ssl=False, timeout=aiohttp.ClientTimeout(total=6)) as resp:
            if resp.status == 200:
                text = await resp.text()
                m = re.search(r"loc=([A-Z]{2})", text)
                if m:
                    return m.group(1)
    except Exception:
        pass

    # Способ 2 (Резервный): ip-api внутри туннеля
    try:
        async with session.get("http://ip-api.com/json/?fields=countryCode", timeout=aiohttp.ClientTimeout(total=6)) as resp:
            if resp.status == 200:
                data = await resp.json()
                cc = data.get("countryCode")
                if cc:
                    return cc
    except Exception:
        pass

    return None


async def test_single_tunnel(node: dict, local_port: int, stats: dict) -> dict | None:
    proxy_url = f"socks5://127.0.0.1:{local_port}"
    connector = ProxyConnector.from_url(proxy_url, rdns=True)
    timeout = aiohttp.ClientTimeout(total=12, connect=6)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            # 1. Проверяем, работает ли туннель и какая у него реальная страна ВЫХОДА
            country = await get_exit_country(session)
            if not country:
                stats["dead_tunnel"] += 1
                return None

            stats["alive_tunnel"] += 1

            if STRICT_US_ONLY and country != "US":
                stats["geo_filtered"] += 1
                return None
            if country in ("RU", "BY", "CN", "HK", "IR", "KP", "SY", "CU"):
                stats["geo_filtered"] += 1
                return None

            # 2. Проверяем доступность Gemini (читаем только первые 32 КБ, не скачивая все 2 МБ страницы)
            t0 = time.monotonic()
            async with session.get("https://gemini.google.com/app", allow_redirects=True, ssl=False) as resp:
                ping_ms = int((time.monotonic() - t0) * 1000)
                final_url = str(resp.url).lower()

                if resp.status not in (200, 302) or ping_ms > MAX_PING_MS:
                    stats["gemini_blocked"] += 1
                    return None

                # Если Google перенаправил на страницу капчи или региональной заглушки
                bad_url_markers = (
                    "google.com/sorry",
                    "policies.google.com/terms/location",
                    "support.google.com/gemini",
                    "gemini.google.com/faq",
                )
                if any(b in final_url for b in bad_url_markers):
                    stats["gemini_blocked"] += 1
                    return None

                chunk = await resp.content.read(32768)
                head_text = chunk.decode("utf-8", errors="ignore")

                # Если открылась страница с WIZ_global_data или редирект на логин Google аккаунта — доступ открыт
                if "WIZ_global_data" in head_text or "accounts.google.com" in final_url or "gemini.google.com" in final_url:
                    node["exit_country"] = country
                    node["gemini_ms"] = ping_ms
                    stats["gemini_ok"] += 1
                    return node

                stats["gemini_blocked"] += 1
                return None
    except Exception:
        stats["dead_tunnel"] += 1
        return None


async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    current_batch = list(batch)

    for _ in range(10):
        if not current_batch:
            return []

        inbounds, outbounds, rules = [], [], []
        for idx, node in enumerate(current_batch):
            port = base_port + idx
            inbounds.append({
                "tag": f"in_{idx}",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True},
            })
            ob = dict(node["outbound"])
            ob["tag"] = f"out_{idx}"
            outbounds.append(ob)
            rules.append({"type": "field", "inboundTag": [f"in_{idx}"], "outboundTag": f"out_{idx}"})

        cfg = {
            "log": {"loglevel": "none"},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }
        with open("xray_temp_config.json", "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        # Перехватываем stdout + stderr вместе, так как Xray пишет ошибки конфига в stdout
        proc = subprocess.Popen(
            ["xray", "run", "-c", "xray_temp_config.json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        await asyncio.sleep(0.9)

        if proc.poll() is None:
            stats = {"alive_tunnel": 0, "dead_tunnel": 0, "geo_filtered": 0, "gemini_blocked": 0, "gemini_ok": 0}
            try:
                tasks = [test_single_tunnel(node, base_port + idx, stats) for idx, node in enumerate(current_batch)]
                results = await asyncio.gather(*tasks)
                print(
                    f"       Статистика пачки: туннелей поднялось={stats['alive_tunnel']} | "
                    f"отсеяно по гео (RU/CN)={stats['geo_filtered']} | "
                    f"блок Google={stats['gemini_blocked']} | "
                    f"GEMINI OK={stats['gemini_ok']}"
                )
                return [r for r in results if r is not None]
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        else:
            err_text = (proc.stdout.read() if proc.stdout else b"").decode("utf-8", errors="ignore")
            m = re.search(r"out_(\d+)", err_text)
            if m:
                bad_idx = int(m.group(1))
                print(f"    [!] Исключен сбойный конфиг out_{bad_idx}, перезапуск пачки...")
                current_batch.pop(bad_idx)
            elif len(current_batch) > 1:
                # Если Xray не указал номер тега, делим пачку пополам, чтобы не терять рабочие серверы
                print(f"    [!] Ошибка конфига в пачке ({err_text.strip()[:120]}), делим пачку пополам...")
                mid = len(current_batch) // 2
                res1 = await run_xray_batch(current_batch[:mid], base_port)
                res2 = await run_xray_batch(current_batch[mid:], base_port + mid)
                return res1 + res2
            else:
                return []

    return []


def flag_emoji(cc: str) -> str:
    return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397) if len(cc) == 2 and cc.isalpha() else "🌐"


async def main():
    nodes = await fetch_sources()
    print("[*] Этап 1: Проверка доступности TCP-портов...")

    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    alive_nodes = [n for n in await asyncio.gather(*(check_tcp(n, sem) for n in nodes)) if n]
    print(f"[+] Доступны по TCP: {len(alive_nodes)} серверов")

    candidates = prioritize_candidates(alive_nodes)
    print(f"[*] Отобрано топ-{len(candidates)} кандидатов для глубокой проверки через Xray...")

    working_nodes = []
    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    -> Тестирование пачки {i + 1}..{i + len(batch)}...")
        passed = await run_xray_batch(batch)
        working_nodes.extend(passed)

    # Сортировка:
    # 1) Серверы с маскировкой под белые списки РФ (WL-RU) и США (US)
    # 2) Великобритания и Европа (GB, NL, DE, FI, SE, FR)
    # 3) Минимальный пинг до Gemini
    working_nodes.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if x["exit_country"] == "US" else (1 if x["exit_country"] in ("GB", "NL", "DE", "FI", "SE", "FR") else 2),
        x["gemini_ms"]
    ))

    final_uris = []
    for idx, n in enumerate(working_nodes, 1):
        cc = n["exit_country"]
        wl_tag = " | WL-RU" if n["whitelist_sni"] else ""
        remark = f"{flag_emoji(cc)} {cc} | Gemini OK | {n['gemini_ms']}ms{wl_tag} | {n['proto'].upper()} #{idx}"
        final_uris.append(rename_uri(n, remark))

    print(f"[*] ИТОГО проверенных рабочих серверов для Gemini: {len(final_uris)}")

    plain_text = "\n".join(final_uris)
    b64_text = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)


if __name__ == "__main__":
    asyncio.run(main())
