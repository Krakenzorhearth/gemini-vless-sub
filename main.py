import asyncio
import base64
import json
import re
import socket
import subprocess
import time
from urllib.parse import parse_qs, quote, unquote, urlparse

import aiohttp
from aiohttp_socks import ProxyConnector

# Публичные агрегаторы бесплатных ключей
SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/all_extracted_configs.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
]

# Настройки фильтрации (ОПТИМИЗИРОВАНО)
TCP_CONCURRENCY = 200
TCP_TIMEOUT = 2.0
MAX_CANDIDATES_FOR_XRAY = 400  # Увеличили выборку до 400 серверов
XRAY_BATCH_SIZE = 50           # Меньшие пачки для стабильности ядра
MAX_PING_MS = 2500             # Увеличили допустимый пинг (бесплатные узлы медленные)
STRICT_US_ONLY = False

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

def safe_b64decode(data: str) -> str:
    # Очистка от мусорных не-ASCII символов, которые ломают парсинг
    data = re.sub(r'[^A-Za-z0-9+/=_-]', '', data)
    data = data.strip().replace("-", "+").replace("_", "/")
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    try:
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def parse_stream_settings(params: dict, default_host: str) -> dict | None:
    net = params.get("type", ["tcp"])[0].lower()
    security = params.get("security", ["none"])[0].lower()
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
    elif net == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", ["/"])[0],
            "headers": {"Host": params.get("host", [default_host])[0]},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0],
            "multiMode": params.get("mode", ["gun"])[0] == "multi",
        }
    elif net in ("httpupgrade", "xhttp", "splithttp"):
        if net == "httpupgrade":
            stream["httpupgradeSettings"] = {
                "path": params.get("path", ["/"])[0],
                "host": params.get("host", [default_host])[0],
            }
        else:
            return None
    else:
        return None

    if security == "tls":
        sni = params.get("sni", [params.get("host", [default_host])[0]])[0]
        tls_cfg = {"serverName": sni, "allowInsecure": True}
        if "fp" in params and params["fp"][0]:
            tls_cfg["fingerprint"] = params["fp"][0]
        if "alpn" in params and params["alpn"][0]:
            tls_cfg["alpn"] = params["alpn"][0].split(",")
        stream["tlsSettings"] = tls_cfg

    elif security == "reality":
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        sni = params.get("sni", [""])[0]
        if not pbk or len(pbk) not in (43, 44) or not HEX_RE.match(sid) or len(sid) > 16:
            return None
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": params.get("fp", ["chrome"])[0] or "chrome",
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": params.get("spx", ["/"])[0],
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
            if not host or not port or not UUID_RE.match(uuid):
                return None
            params = parse_qs(parsed.query)
            stream = parse_stream_settings(params, host)
            if not stream:
                return None
            flow = params.get("flow", [""])[0]
            if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                return None
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": int(port),
                        "users": [{"id": uuid, "encryption": params.get("encryption", ["none"])[0], "flow": flow}],
                    }]
                },
                "streamSettings": stream,
            }
            return {"uri": uri, "proto": "vless", "host": host, "port": int(port), "key": f"vless:{host}:{port}:{uuid}", "remark": unquote(parsed.fragment), "outbound": outbound}

        elif uri.startswith("trojan://"):
            parsed = urlparse(uri)
            password = unquote(parsed.username or "")
            host = parsed.hostname
            port = parsed.port
            if not host or not port or not password:
                return None
            params = parse_qs(parsed.query)
            if "security" not in params:
                params["security"] = ["tls"]
            stream = parse_stream_settings(params, host)
            if not stream:
                return None
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": int(port), "password": password}]},
                "streamSettings": stream,
            }
            return {"uri": uri, "proto": "trojan", "host": host, "port": int(port), "key": f"trojan:{host}:{port}:{password}", "remark": unquote(parsed.fragment), "outbound": outbound}

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
            if method.lower().strip() not in SUPPORTED_SS_CIPHERS:
                return None

            hostport = hostport.split("?")[0].strip("/")
            parsed_hp = urlparse(f"http://{hostport}")
            host, port = parsed_hp.hostname, parsed_hp.port
            if not host or not port or not password:
                return None

            outbound = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": host, "port": int(port), "method": method.lower().strip(), "password": password}]},
                "streamSettings": {"network": "tcp", "security": "none"},
            }
            return {"uri": uri, "proto": "ss", "host": host, "port": int(port), "key": f"ss:{host}:{port}:{method}:{password}", "remark": remark, "outbound": outbound}
    except Exception:
        return None
    return None

def rename_uri(node: dict, new_remark: str) -> str:
    base_uri = node["uri"].split("#")[0]
    return f"{base_uri}#{quote(new_remark)}"

async def fetch_sources() -> list[dict]:
    raw_lines = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        for url in SOURCES:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "://" not in text[:200]:
                            text = safe_b64decode(text)
                        if text:
                            raw_lines.extend(text.splitlines())
                        print(f"[+] Загружен источник: {url}")
            except Exception as e:
                print(f"[-] Ошибка загрузки {url}: {e}")

    nodes = {}
    for line in raw_lines:
        line = line.strip()
        if line.startswith(("vless://", "trojan://", "ss://")):
            parsed = parse_proxy_uri(line)
            if parsed and parsed["key"] not in nodes:
                nodes[parsed["key"]] = parsed
    print(f"[*] Уникальных валидных конфигов: {len(nodes)}")
    return list(nodes.values())

async def check_tcp(node: dict, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(node["host"], node["port"])
            reader, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
            writer.close()
            await writer.wait_closed()
            node["tcp_ms"] = int((time.monotonic() - t0) * 1000)
            return node
        except Exception:
            return None

async def enrich_geoip_and_prioritize(nodes: list[dict]) -> list[dict]:
    for n in nodes:
        try:
            n["ip"] = socket.gethostbyname(n["host"])
        except Exception:
            n["ip"] = n["host"]

    unique_ips = list({n["ip"] for n in nodes if n.get("ip")})
    ip_country = {}

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        for i in range(0, len(unique_ips), 100):
            batch = unique_ips[i:i + 100]
            try:
                async with session.post("http://ip-api.com/batch?fields=query,countryCode", json=batch) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data:
                            ip_country[item.get("query")] = item.get("countryCode", "UN")
            except Exception:
                pass

    us_keywords = ("US", "USA", "🇺🇸", "United States")
    for n in nodes:
        cc = ip_country.get(n["ip"], "UN")
        has_us_tag = any(k.lower() in n["remark"].lower() for k in us_keywords)
        n["is_likely_us"] = (cc == "US") or has_us_tag
        n["sort_key"] = (0 if n["is_likely_us"] else 1, 0 if n["proto"] == "vless" else 1, n["tcp_ms"])

    nodes.sort(key=lambda x: x["sort_key"])
    return nodes[:MAX_CANDIDATES_FOR_XRAY]

async def test_single_tunnel(node: dict, local_port: int) -> dict | None:
    proxy_url = f"socks5://127.0.0.1:{local_port}"
    connector = ProxyConnector.from_url(proxy_url)
    timeout = aiohttp.ClientTimeout(total=8, connect=4)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            async with session.get("https://1.1.1.1/cdn-cgi/trace") as trace_resp:
                if trace_resp.status != 200: return None
                country = re.search(r"loc=([A-Z]{2})", await trace_resp.text()).group(1) or "UN"

            if STRICT_US_ONLY and country != "US": return None
            if country in ("RU", "BY", "CN", "IR"): return None

            t0 = time.monotonic()
            async with session.get("https://gemini.google.com/app", allow_redirects=True) as resp:
                ping_ms = int((time.monotonic() - t0) * 1000)
                final_url = str(resp.url).lower()
                
                if resp.status != 200 or ping_ms > MAX_PING_MS: return None
                if any(m in final_url for m in ("sorry", "unsupported", "location", "policies")): return None
                
                body = (await resp.text())[:3000].lower()
                if "currently not supported" in body or "не поддерживается" in body: return None

                node["exit_country"] = country
                node["gemini_ms"] = ping_ms
                return node
    except Exception:
        return None

async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    if not batch: return []

    inbounds, outbounds, rules = [], [], []
    for idx, node in enumerate(batch):
        port = base_port + idx
        inbounds.append({"tag": f"in_{idx}", "port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth", "udp": False}})
        ob = dict(node["outbound"])
        ob["tag"] = f"out_{idx}"
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in_{idx}"], "outboundTag": f"out_{idx}"})

    with open("xray_temp_config.json", "w", encoding="utf-8") as f:
        json.dump({"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": rules}}, f)

    # Используем PIPE для перехвата ошибок, чтобы скрипт не висел
    proc = subprocess.Popen(["xray", "run", "-c", "xray_temp_config.json"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    await asyncio.sleep(1.5)

    if proc.poll() is not None:
        err = proc.stderr.read().decode('utf-8', errors='ignore')
        print(f"    [!] Ядро Xray аварийно завершилось из-за битого конфига в этой пачке. Пропускаем. Ошибка: {err[:150]}")
        return []

    try:
        tasks = [test_single_tunnel(node, base_port + idx) for idx, node in enumerate(batch)]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
    finally:
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill()

def flag_emoji(cc: str) -> str:
    return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397) if len(cc) == 2 and cc.isalpha() else "🌐"

async def main():
    nodes = await fetch_sources()
    print("[*] Этап 1: Проверка доступности TCP-портов...")
    
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    alive_nodes = [n for n in await asyncio.gather(*(check_tcp(n, sem) for n in nodes)) if n]
    print(f"[+] Доступны по TCP: {len(alive_nodes)} серверов")

    candidates = await enrich_geoip_and_prioritize(alive_nodes)
    print(f"[*] Отобрано топ-{len(candidates)} кандидатов для проверки через Xray и Gemini...")

    working_nodes = []
    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    -> Тестирование пачки {i + 1}..{i + len(batch)}...")
        passed = await run_xray_batch(batch)
        working_nodes.extend(passed)
        if passed: print(f"    [+] Найдено рабочих для Gemini: {len(passed)}")

    working_nodes.sort(key=lambda x: (0 if x["exit_country"] == "US" else 1, x["gemini_ms"]))
    
    final_uris = [rename_uri(n, f"{flag_emoji(n['exit_country'])} {n['exit_country']} | Gemini OK | {n['gemini_ms']}ms | {n['proto'].upper()} #{idx}") for idx, n in enumerate(working_nodes, 1)]
    print(f"[*] ИТОГО проверенных серверов для Gemini: {len(final_uris)}")

    with open("sub.txt", "w", encoding="utf-8") as f: f.write("\n".join(final_uris))
    with open("sub_base64.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode("\n".join(final_uris).encode("utf-8")).decode("utf-8"))

if __name__ == "__main__":
    asyncio.run(main())
