import asyncio
import base64
import ipaddress
import json
import re
import subprocess
import time
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse

import aiohttp

SOURCES = [
    # 1. VLESS-PO-GRIBI
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/5.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/6.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/8.txt",
    # 2. igareck/vpn-configs-for-russia (проверенные VLESS Reality + белые списки)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    # 3. rjsxrd + профильные базы обхода белых списков
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    # 4. Глобальные агрегаторы VLESS
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
]

TCP_CONCURRENCY = 200
TCP_TIMEOUT = 2.0
MAX_CANDIDATES_FOR_XRAY = 400
XRAY_BATCH_SIZE = 40
MAX_PING_MS = 4000
STRICT_US_ONLY = False

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
GOOGLE_LOC_RE = re.compile(r',2,1,200,"([A-Z]{3})"')

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
VALID_ALPNS = {"h2", "http/1.1", "h3"}

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

BAD_EXIT_REMARK_MARKERS = ("🇷🇺", "| RUS", "Russia", "Россия", "Москва", "СПб", "🇧🇾", "🇨🇳", "🇮🇷")
BLOCKED_ISO3 = {"RUS", "BLR", "CHN", "HKG", "MAC", "IRN", "PRK", "CUB", "SYR", "AFG"}

ISO3_TO_ISO2 = {
    "USA": "US", "GBR": "GB", "NLD": "NL", "DEU": "DE", "FIN": "FI",
    "SWE": "SE", "FRA": "FR", "POL": "PL", "EST": "EE", "LVA": "LV",
    "LTU": "LT", "CAN": "CA", "CHE": "CH", "AUT": "AT", "ESP": "ES",
    "ITA": "IT", "NOR": "NO", "DNK": "DK", "IRL": "IE", "CZE": "CZ",
    "SGP": "SG", "JPN": "JP", "KOR": "KR", "TUR": "TR", "KAZ": "KZ",
}

COUNTRY_HINTS = {
    "🇺🇸": "US", "USA": "US", "United States": "US", "| US": "US", "_US": "US",
    "🇬🇧": "GB", "GBR": "GB", "UK": "GB", "英国": "GB",
    "🇳🇱": "NL", "NLD": "NL", "Netherlands": "NL", "| NL": "NL",
    "🇩🇪": "DE", "DEU": "DE", "Germany": "DE", "| DE": "DE",
    "🇫🇮": "FI", "FIN": "FI", "Finland": "FI", "| FI": "FI",
    "🇸🇪": "SE", "SWE": "SE", "Sweden": "SE",
    "🇫🇷": "FR", "FRA": "FR", "France": "FR",
    "🇵🇱": "PL", "POL": "PL", "Poland": "PL",
    "🇪🇪": "EE", "EST": "EE",
    "🇱🇻": "LV", "LVA": "LV",
    "🇨🇦": "CA", "CAN": "CA",
}


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


def guess_country_from_remark(remark: str) -> str:
    for marker, cc in COUNTRY_HINTS.items():
        if marker in remark:
            return cc
    return "EU"


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
        if params.get("allowInsecure", ["0"])[0] in ("1", "true") or params.get("insecure", ["0"])[0] in ("1", "true"):
            return None
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
            remark = unquote(parsed.fragment)
            if any(bad in remark for bad in BAD_EXIT_REMARK_MARKERS):
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
                "key": f"vless:{host}:{port}:{uuid}", "remark": remark,
                "outbound": outbound,
            }
    except Exception:
        return None
    return None


def rename_uri(node: dict, new_remark: str) -> str:
    base_uri = node["uri"].split("#")[0]
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
        for url in SOURCES:
            src_prio = 0 if any(k in url for k in ("VLESS-PO-GRIBI", "igareck", "rjsxrd", "LowiKLive")) else 1
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
                                if line.startswith("vless://"):
                                    parsed = parse_proxy_uri(line, src_prio)
                                    if parsed and parsed["key"] not in nodes:
                                        nodes[parsed["key"]] = parsed
                                        added += 1
                            print(f"[+] Источник ({added} новых узлов): {url}")
            except Exception as e:
                print(f"[-] Пропущен источник {url}: {e}")

    print(f"[*] Всего уникальных валидных VLESS-конфигов (без RU-выходов): {len(nodes)}")
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
    filtered = [n for n in nodes if not is_cloudflare_ip(n.get("ip", ""))]
    print(f"[*] После отсева пустышек Cloudflare осталось: {len(filtered)} серверов")

    for n in filtered:
        guessed_cc = guess_country_from_remark(n["remark"])
        has_explicit_foreign_flag = guessed_cc != "EU"
        is_us_or_uk = guessed_cc in ("US", "GB")

        n["sort_key"] = (
            0 if (n["whitelist_sni"] and has_explicit_foreign_flag) else 1,
            n["source_prio"],
            0 if n["is_reality"] else 1,
            0 if is_us_or_uk else (1 if has_explicit_foreign_flag else 2),
            n["tcp_ms"],
        )

    filtered.sort(key=lambda x: x["sort_key"])
    return filtered[:MAX_CANDIDATES_FOR_XRAY]


async def test_single_tunnel(node: dict, local_port: int, stats: dict) -> dict | None:
    proxy_addr = f"http://127.0.0.1:{local_port}"

    try:
        # Шаг 1: Быстрый замер чистого пинга до Google через пустой 204-ответ
        t0 = time.monotonic()
        proc_ping = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null",
            "-x", proxy_addr,
            "--connect-timeout", "5",
            "--max-time", "7",
            "-w", "%{http_code}",
            "https://www.google.com/generate_204",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out_ping, _ = await asyncio.wait_for(proc_ping.communicate(), timeout=8)
        ping_code = out_ping.decode("utf-8", errors="ignore").strip()

        if ping_code not in ("204", "200"):
            stats["dead_tunnel"] += 1
            return None

        ping_ms = int((time.monotonic() - t0) * 1000)
        if ping_ms > MAX_PING_MS:
            stats["dead_tunnel"] += 1
            return None

        # Шаг 2: Запрос к https://gemini.google.com/ через нативный curl
        proc_gem = await asyncio.create_subprocess_exec(
            "curl", "-sL",
            "-x", proxy_addr,
            "--connect-timeout", "5",
            "--max-time", "10",
            "-H", "Accept-Language: en-US,en;q=0.9",
            "-w", "\n__CURL_META__:%{http_code}|%{url_effective}",
            "https://gemini.google.com/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out_gem, _ = await asyncio.wait_for(proc_gem.communicate(), timeout=12)
        raw_text = out_gem.decode("utf-8", errors="ignore")

        if "__CURL_META__:" not in raw_text:
            stats["dead_tunnel"] += 1
            return None

        html_body, meta_part = raw_text.rsplit("__CURL_META__:", 1)
        http_code, final_url = meta_part.strip().split("|", 1)
        final_url_low = final_url.lower()
        stats["alive_tunnel"] += 1

        # 1. Отсекаем явные редиректы на блокировку региона или капчу Google
        bad_url_markers = (
            "/faq",
            "google.com/sorry",
            "policies.google.com",
            "support.google.com",
            "unsupported",
        )
        if http_code != "200" or any(b in final_url_low for b in bad_url_markers):
            print(f"       [-] Блок по URL/коду ({http_code} -> {final_url[:60]}): {node['host']}")
            stats["gemini_blocked"] += 1
            return None

        # 2. Отсекаем явный флаг регионального бана внутри HTML (если Google прислал полную страницу)
        if '"45631641":false' in html_body or "[45631641,null,false" in html_body:
            print(f"       [-] Блок по флагу 45631641=false: {node['host']}")
            stats["gemini_blocked"] += 1
            return None

        # 3. Проверяем 3-буквенный код страны Google (,2,1,200,"GBR"), если он присутствует в ответе
        loc_match = GOOGLE_LOC_RE.search(html_body)
        if loc_match:
            iso3 = loc_match.group(1)
            if iso3 in BLOCKED_ISO3:
                print(f"       [-] Блок по гео-метке Google ({iso3}): {node['host']}")
                stats["gemini_blocked"] += 1
                return None
            country = ISO3_TO_ISO2.get(iso3, guess_country_from_remark(node["remark"]))
        else:
            country = guess_country_from_remark(node["remark"])

        if STRICT_US_ONLY and country != "US":
            return None

        node["exit_country"] = country
        node["gemini_ms"] = ping_ms
        stats["gemini_ok"] += 1
        print(f"       [✓] GEMINI OK: {node['host']}:{node['port']} ({country}) | {ping_ms}ms | {node['remark'][:45]}")
        return node

    except Exception:
        stats["dead_tunnel"] += 1
        return None


async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    current_batch = list(batch)

    # Удаляем битые конфиги до тех пор, пока пачка не запустится
    while current_batch:
        inbounds, outbounds, rules = [], [], []
        for idx, node in enumerate(current_batch):
            port = base_port + idx
            inbounds.append({
                "tag": f"in_{idx}",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"userLevel": 8},
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

        proc = subprocess.Popen(
            ["xray", "run", "-c", "xray_temp_config.json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        await asyncio.sleep(0.6)

        if proc.poll() is None:
            stats = {"alive_tunnel": 0, "dead_tunnel": 0, "gemini_blocked": 0, "gemini_ok": 0}
            try:
                tasks = [test_single_tunnel(node, base_port + idx, stats) for idx, node in enumerate(current_batch)]
                results = await asyncio.gather(*tasks)
                print(
                    f"       Итог пачки: ответили={stats['alive_tunnel']} | "
                    f"блок региона={stats['gemini_blocked']} | "
                    f"таймаут={stats['dead_tunnel']} | "
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
                current_batch.pop(bad_idx)
            elif len(current_batch) > 1:
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
