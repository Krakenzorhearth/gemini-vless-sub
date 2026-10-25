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

# Целевые источники: rjsxrd (bypass белых списков РФ) + VLESS-PO-GRIBI
SOURCES = [
    # Специальная выборка с обходом белых списков РФ (SNI ozon.ru, vk.com и т.д.)
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/all-secure.txt",
    # Подписки из репозитория VLESS-PO-GRIBI
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/5.txt",
    "https://raw.githubusercontent.com/histeenn/VLESS-PO-GRIBI/main/deploy/subscriptions/6.txt",
    # Fallback-ссылки VLESS-PO-GRIBI (старый алиас владельца)
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
]

TCP_CONCURRENCY = 200
TCP_TIMEOUT = 2.0
MAX_CANDIDATES_FOR_XRAY = 300
XRAY_BATCH_SIZE = 50
MAX_PING_MS = 3500
STRICT_US_ONLY = False  # False оставляет США (в начале списка) + Великобританию/Европу (где работает Gemini и ниже пинг)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
VALID_ALPNS = {"h2", "http/1.1", "h3"}
SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

# Диапазоны Cloudflare (отсекаем их от попадания в топ, т.к. они дают фейковый TCP-пинг 2мс)
CF_NETS = [
    ipaddress.ip_network("104.16.0.0/12"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("198.41.128.0/17"),
]

# Домены из белых списков РФ (как gb.ozon.ru в твоем примере)
RU_WHITELIST_MARKERS = (".ru", "ozon", "yandex", "vk.com", "userapi", "wb.ru", "wildberries", "mail.ru", "kaspersky")


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
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0],
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
        if not sni:
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
        if not sni or not is_valid_reality_pbk(pbk):
            return None
        if sid and (len(sid) > 16 or len(sid) % 2 != 0 or not HEX_RE.match(sid)):
            return None
        fp = params.get("fp", ["firefox"])[0].lower()
        spx = params.get("spx", ["/"])[0].strip()
        if not spx.startswith("/"):
            spx = "/"
        # Точная структура из твоего рабочего JSON
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


def parse_proxy_uri(uri: str) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vless://"):
            parsed = urlparse(uri)
            uuid = unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            if not host or not port or not (1 <= int(port) <= 65535) or not UUID_RE.match(uuid):
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
                "key": f"vless:{host}:{port}:{uuid}", "remark": unquote(parsed.fragment),
                "outbound": outbound,
            }

        elif uri.startswith("trojan://"):
            parsed = urlparse(uri)
            password = unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            if not host or not port or not (1 <= int(port) <= 65535) or not password:
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
                "key": f"trojan:{host}:{port}:{password}", "remark": unquote(parsed.fragment),
                "outbound": outbound,
            }

        elif uri.startswith("ss://"):
            main_part, _, fragment = uri[5:].partition("#")
            remark = unquote(fragment)
            if "@" in main_part:
                userinfo_b64, hostport = main_part.rsplit("@", 1)
                userinfo = safe_b64decode(unquote(userinfo_b64))
            else:
                decoded = safe_b64decode(main_part)
                if not decoded or "@" not in decoded:
                    return None
                userinfo, hostport = decoded.rsplit("@", 1)

            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)
            method = method.lower().strip()
            if method not in SUPPORTED_SS_CIPHERS or not password:
                return None

            hostport = hostport.split("?")[0].strip("/")
            parsed_hp = urlparse(f"http://{hostport}")
            host, port = parsed_hp.hostname, parsed_hp.port
            if not host or not port or not (1 <= int(port) <= 65535):
                return None

            outbound = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": int(port), "method": method, "password": password, "level": 8}]},
                "streamSettings": {"network": "tcp", "security": "none"},
            }
            return {
                "uri": uri, "proto": "ss", "host": host, "port": int(port),
                "is_reality": False, "whitelist_sni": False,
                "key": f"ss:{host}:{port}:{method}:{password}", "remark": remark,
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
    raw_lines = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        for url in SOURCES:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        raw_bytes = await resp.read()
                        text = raw_bytes.decode("utf-8", errors="ignore")
                        if "://" not in text[:300]:
                            text = safe_b64decode(text)
                        if text:
                            lines = text.splitlines()
                            raw_lines.extend(lines)
                            print(f"[+] Загружен источник ({len(lines)} строк): {url}")
            except Exception as e:
                print(f"[-] Пропущен источник {url}: {e}")

    nodes = {}
    for line in raw_lines:
        line = line.strip()
        if line.startswith(("vless://", "trojan://", "ss://")):
            parsed = parse_proxy_uri(line)
            if parsed and parsed["key"] not in nodes:
                nodes[parsed["key"]] = parsed
    print(f"[*] Уникальных валидных конфигов после парсинга: {len(nodes)}")
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


async def enrich_geoip_and_prioritize(nodes: list[dict]) -> list[dict]:
    # Отсеиваем фейковые Anycast-узлы Cloudflare
    filtered = [n for n in nodes if not is_cloudflare_ip(n.get("ip", ""))]
    print(f"[*] После отсева пустышек Cloudflare осталось: {len(filtered)} серверов")

    unique_ips = list({n["ip"] for n in filtered if n.get("ip") and ":" not in n["ip"]})
    ip_country = {}

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        for i in range(0, len(unique_ips), 100):
            batch = unique_ips[i:i + 100]
            try:
                async with session.post("http://ip-api.com/batch?fields=query,countryCode", json=batch) as resp:
                    if resp.status == 200:
                        for item in await resp.json():
                            ip_country[item.get("query")] = item.get("countryCode", "UN")
            except Exception:
                pass

    us_keywords = ("US", "USA", "🇺🇸", "United States")
    for n in filtered:
        cc = ip_country.get(n.get("ip"), "UN")
        if cc in ("RU", "BY", "CN", "IR"):
            n["skip"] = True
            continue
        n["skip"] = False
        has_us_tag = any(k.lower() in n["remark"].lower() for k in us_keywords)
        is_us = (cc == "US") or has_us_tag

        # Приоритет: 1) VLESS Reality (особенно с белыми списками РФ), 2) США и Европа, 3) минимальный TCP-пинг
        reality_prio = 0 if n["is_reality"] else 1
        whitelist_prio = 0 if n["whitelist_sni"] else 1
        us_prio = 0 if is_us else 1
        n["sort_key"] = (reality_prio, whitelist_prio, us_prio, n["tcp_ms"])

    valid_candidates = [n for n in filtered if not n.get("skip")]
    valid_candidates.sort(key=lambda x: x["sort_key"])
    return valid_candidates[:MAX_CANDIDATES_FOR_XRAY]


async def test_single_tunnel(node: dict, local_port: int) -> dict | None:
    proxy_url = f"socks5://127.0.0.1:{local_port}"
    connector = ProxyConnector.from_url(proxy_url, rdns=True)
    timeout = aiohttp.ClientTimeout(total=10, connect=5)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            # 1. Проверяем реальный выходной IP и страну
            async with session.get("https://www.cloudflare.com/cdn-cgi/trace", ssl=False) as trace_resp:
                if trace_resp.status != 200:
                    return None
                trace_text = await trace_resp.text()
                m = re.search(r"loc=([A-Z]{2})", trace_text)
                country = m.group(1) if m else "UN"

            if STRICT_US_ONLY and country != "US":
                return None
            if country in ("RU", "BY", "CN", "HK", "IR", "KP", "SY", "CU"):
                return None

            # 2. Проверяем доступность Gemini
            t0 = time.monotonic()
            async with session.get("https://gemini.google.com/", allow_redirects=True, ssl=False) as resp:
                ping_ms = int((time.monotonic() - t0) * 1000)
                final_url = str(resp.url).lower()

                if resp.status not in (200, 302) or ping_ms > MAX_PING_MS:
                    return None

                bad_markers = ("sorry", "unsupported", "location", "policies.google.com", "support.google.com/gemini/answer")
                if any(b in final_url for b in bad_markers):
                    return None

                body = (await resp.text())[:5000].lower()
                if "currently not supported" in body or "не поддерживается" in body:
                    return None

                node["exit_country"] = country
                node["gemini_ms"] = ping_ms
                return node
    except Exception:
        return None


async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    current_batch = list(batch)

    for _ in range(10):
        if not current_batch:
            return []

        inbounds, outbounds, rules = [], [], []
        for idx, node in enumerate(current_batch):
            port = base_port + idx
            # Inbound в точности повторяет настройки твоего рабочего JSON (включая sniffing и udp)
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
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        }
        with open("xray_temp_config.json", "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen(
            ["xray", "run", "-c", "xray_temp_config.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE
        )
        await asyncio.sleep(1.0)

        if proc.poll() is None:
            try:
                tasks = [test_single_tunnel(node, base_port + idx) for idx, node in enumerate(current_batch)]
                results = await asyncio.gather(*tasks)
                return [r for r in results if r is not None]
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
        else:
            err_text = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", errors="ignore")
            m = re.search(r"out_(\d+)", err_text)
            if m:
                bad_idx = int(m.group(1))
                print(f"    [!] Исключен битый конфиг #{bad_idx}, перезапуск пачки...")
                current_batch.pop(bad_idx)
            else:
                print(f"    [!] Ошибка старта пачки Xray: {err_text.strip()[:180]}")
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

    candidates = await enrich_geoip_and_prioritize(alive_nodes)
    print(f"[*] Отобрано топ-{len(candidates)} кандидатов (приоритет VLESS Reality + белые списки РФ)...")

    working_nodes = []
    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    -> Тестирование пачки {i + 1}..{i + len(batch)}...")
        passed = await run_xray_batch(batch)
        working_nodes.extend(passed)
        print(f"    [+] Найдено рабочих для Gemini в пачке: {len(passed)}")

    # Сортировка: сначала серверы с обходом белых списков РФ + США/Великобритания, затем по минимальному пингу
    working_nodes.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if x["exit_country"] == "US" else (1 if x["exit_country"] in ("GB", "NL", "DE", "FI") else 2),
        x["gemini_ms"]
    ))

    final_uris = []
    for idx, n in enumerate(working_nodes, 1):
        cc = n["exit_country"]
        wl_tag = " | WL-RU" if n["whitelist_sni"] else ""
        remark = f"{flag_emoji(cc)} {cc} | Gemini OK | {n['gemini_ms']}ms{wl_tag} | {n['proto'].upper()} #{idx}"
        final_uris.append(rename_uri(n, remark))

    print(f"[*] ИТОГО проверенных серверов для Gemini: {len(final_uris)}")

    plain_text = "\n".join(final_uris)
    b64_text = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)


if __name__ == "__main__":
    asyncio.run(main())
