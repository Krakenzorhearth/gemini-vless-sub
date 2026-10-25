import asyncio
import base64
import json
import os
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
]

# Настройки фильтрации
TCP_CONCURRENCY = 200
TCP_TIMEOUT = 1.5
MAX_CANDIDATES_FOR_XRAY = 240  # Сколько лучших TCP-живых узлов прогонять через Xray
XRAY_BATCH_SIZE = 60           # Количество параллельных туннелей в одном процессе Xray
MAX_PING_MS = 1800             # Максимальный допустимый пинг до Gemini (мс)
STRICT_US_ONLY = False         # True — оставлять строго США; False — США в приоритете + другие страны, где работает Gemini

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

SUPPORTED_SS_CIPHERS = {
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305",
    "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}


def safe_b64decode(data: str) -> str:
    data = data.strip().replace("-", "+").replace("_", "/")
    padding = len(data) % 4
    if padding:
        data += "=" * (4 - padding)
    return base64.b64decode(data).decode("utf-8", errors="ignore")


def parse_stream_settings(params: dict, default_host: str) -> dict | None:
    net = params.get("type", ["tcp"])[0].lower()
    security = params.get("security", ["none"])[0].lower()

    stream = {"network": net, "security": security}

    # Настройка транспорта
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

    # Настройка TLS / Reality
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
        # Отсев битых Reality-ключей, из-за которых падает Xray
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
                        "users": [{
                            "id": uuid,
                            "encryption": params.get("encryption", ["none"])[0],
                            "flow": flow,
                        }],
                    }]
                },
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "vless", "host": host, "port": int(port),
                "key": f"vless:{host}:{port}:{uuid}", "remark": unquote(parsed.fragment),
                "outbound": outbound,
            }

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
                "settings": {
                    "servers": [{"address": host, "port": int(port), "password": password}]
                },
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "trojan", "host": host, "port": int(port),
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
                if "@" not in decoded:
                    return None
                userinfo, hostport = decoded.rsplit("@", 1)

            if ":" not in userinfo:
                return None
            method, password = userinfo.split(":", 1)
            method = method.lower().strip()
            if method not in SUPPORTED_SS_CIPHERS:
                return None

            hostport = hostport.split("?")[0].strip("/")
            parsed_hp = urlparse(f"http://{hostport}")
            host, port = parsed_hp.hostname, parsed_hp.port
            if not host or not port or not password:
                return None

            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host, "port": int(port),
                        "method": method, "password": password,
                    }]
                },
                "streamSettings": {"network": "tcp", "security": "none"},
            }
            return {
                "uri": uri, "proto": "ss", "host": host, "port": int(port),
                "key": f"ss:{host}:{port}:{method}:{password}", "remark": remark,
                "outbound": outbound,
            }

        elif uri.startswith("vmess://"):
            raw_json = safe_b64decode(uri[8:])
            data = json.loads(raw_json)
            host = str(data.get("add", "")).strip()
            port = int(data.get("port", 0))
            uuid = str(data.get("id", "")).strip()
            if not host or not port or not UUID_RE.match(uuid):
                return None
            net = str(data.get("net", "tcp")).lower()
            tls_val = str(data.get("tls", "none")).lower()
            security = "tls" if tls_val == "tls" else "none"
            params = {
                "type": [net],
                "security": [security],
                "path": [str(data.get("path", "/") or "/")],
                "host": [str(data.get("host", host) or host)],
                "sni": [str(data.get("sni", host) or host)],
                "serviceName": [str(data.get("path", ""))],
            }
            stream = parse_stream_settings(params, host)
            if not stream:
                return None
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{
                            "id": uuid,
                            "alterId": int(data.get("aid", 0)),
                            "security": str(data.get("scy", "auto") or "auto"),
                        }],
                    }]
                },
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "vmess", "host": host, "port": port,
                "key": f"vmess:{host}:{port}:{uuid}", "remark": str(data.get("ps", "")),
                "vmess_json": data, "outbound": outbound,
            }
    except Exception:
        return None
    return None


def rename_uri(node: dict, new_remark: str) -> str:
    if node["proto"] == "vmess":
        data = dict(node["vmess_json"])
        data["ps"] = new_remark
        encoded = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
        return f"vmess://{encoded}"
    else:
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
                        raw_lines.extend(text.splitlines())
                        print(f"[+] Загружен источник: {url}")
            except Exception as e:
                print(f"[-] Ошибка загрузки {url}: {e}")

    nodes = {}
    for line in raw_lines:
        line = line.strip()
        if line.startswith(("vless://", "trojan://", "ss://", "vmess://")):
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
            writer.close()
            await writer.wait_closed()
            node["tcp_ms"] = int((time.monotonic() - t0) * 1000)
            return node
        except Exception:
            return None


async def enrich_geoip_and_prioritize(nodes: list[dict]) -> list[dict]:
    # Резолвим хосты для быстрой пакетной проверки через ip-api
    loop = asyncio.get_running_loop()
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

    us_keywords = ("US", "USA", "🇺🇸", "United States", "America")
    for n in nodes:
        cc = ip_country.get(n["ip"], "UN")
        has_us_tag = any(k.lower() in n["remark"].lower() for k in us_keywords)
        n["is_likely_us"] = (cc == "US") or has_us_tag
        # Приоритет: 1) VLESS + US, 2) Другие протоколы + US, 3) Остальные быстрые по пингу
        proto_Priority = 0 if n["proto"] == "vless" else 1
        us_priority = 0 if n["is_likely_us"] else 1
        n["sort_key"] = (us_priority, proto_Priority, n["tcp_ms"])

    nodes.sort(key=lambda x: x["sort_key"])
    return nodes[:MAX_CANDIDATES_FOR_XRAY]


async def test_single_tunnel(node: dict, local_port: int) -> dict | None:
    proxy_url = f"socks5://127.0.0.1:{local_port}"
    connector = ProxyConnector.from_url(proxy_url)
    timeout = aiohttp.ClientTimeout(total=7, connect=4)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
            # 1. Определяем реальную страну выходного IP через Cloudflare Trace
            async with session.get("https://1.1.1.1/cdn-cgi/trace") as trace_resp:
                if trace_resp.status != 200:
                    return None
                trace_text = await trace_resp.text()
                loc_match = re.search(r"loc=([A-Z]{2})", trace_text)
                country = loc_match.group(1) if loc_match else "UN"

            if STRICT_US_ONLY and country != "US":
                return None
            if country in ("RU", "BY", "CN", "HK", "IR", "KP"):
                return None

            # 2. Проверяем доступность Gemini
            t0 = time.monotonic()
            async with session.get("https://gemini.google.com/app", allow_redirects=True) as resp:
                ping_ms = int((time.monotonic() - t0) * 1000)
                final_url = str(resp.url).lower()

                if resp.status != 200 or ping_ms > MAX_PING_MS:
                    return None

                # Отсекаем редиректы на блокировку локации или капчу Google
                bad_url_markers = ("sorry", "unsupported", "location", "policies.google.com", "support.google.com")
                if any(m in final_url for m in bad_url_markers):
                    return None

                body_sample = (await resp.text())[:4000].lower()
                if "currently not supported" in body_sample or "не поддерживается" in body_sample:
                    return None

                node["exit_country"] = country
                node["gemini_ms"] = ping_ms
                return node
    except Exception:
        return None


async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    if not batch:
        return []

    inbounds = []
    outbounds = []
    rules = []

    for idx, node in enumerate(batch):
        port = base_port + idx
        in_tag = f"in_{idx}"
        out_tag = f"out_{idx}"

        inbounds.append({
            "tag": in_tag,
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        })

        ob = dict(node["outbound"])
        ob["tag"] = out_tag
        outbounds.append(ob)

        rules.append({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": out_tag,
        })

    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }

    cfg_path = "xray_temp_config.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    proc = subprocess.Popen(["xray", "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    await asyncio.sleep(1.2)

    # Если из-за какого-то нестандартного конфига Xray упал при старте — делим пачку пополам
    if proc.poll() is not None:
        if len(batch) <= 1:
            return []
        mid = len(batch) // 2
        res1 = await run_xray_batch(batch[:mid], base_port)
        res2 = await run_xray_batch(batch[mid:], base_port + mid)
        return res1 + res2

    try:
        tasks = [test_single_tunnel(node, base_port + idx) for idx, node in enumerate(batch)]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()


def flag_emoji(cc: str) -> str:
    if len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397)


async def main():
    nodes = await fetch_sources()

    print("[*] Этап 1: Проверка доступности TCP-портов...")
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    tcp_results = await asyncio.gather(*(check_tcp(n, sem) for n in nodes))
    alive_nodes = [n for n in tcp_results if n is not None]
    print(f"[+] Доступны по TCP: {len(alive_nodes)} серверов")

    candidates = await enrich_geoip_and_prioritize(alive_nodes)
    print(f"[*] Отобрано топ-{len(candidates)} кандидатов для проверки через Xray и Gemini...")

    working_nodes = []
    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    -> Тестирование пачки {i + 1}..{i + len(batch)}...")
        passed = await run_xray_batch(batch)
        working_nodes.extend(passed)
        print(f"    [+] Найдено рабочих в пачке: {len(passed)}")

    # Сортировка: сначала US, затем VLESS, затем по минимальному пингу до Gemini
    working_nodes.sort(key=lambda x: (
        0 if x["exit_country"] == "US" else 1,
        0 if x["proto"] == "vless" else 1,
        x["gemini_ms"]
    ))

    final_uris = []
    for idx, node in enumerate(working_nodes, 1):
        cc = node["exit_country"]
        flag = flag_emoji(cc)
        proto_up = node["proto"].upper()
        remark = f"{flag} {cc} | Gemini OK | {node['gemini_ms']}ms | {proto_up} #{idx}"
        final_uris.append(rename_uri(node, remark))

    print(f"[*] ИТОГО проверенных серверов для Gemini: {len(final_uris)}")

    plain_text = "\n".join(final_uris)
    b64_text = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8")

    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)

    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64_text)


if __name__ == "__main__":
    asyncio.run(main())
