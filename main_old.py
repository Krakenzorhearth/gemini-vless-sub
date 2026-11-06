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
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/vless.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/5.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/6.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/8.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/Splitted-By-Protocol/vless.txt",
]

# --- ИЗМЕНЕННЫЕ ЛИМИТЫ ДЛЯ МАССОВКИ ---
STRICT_WL_RU = False           # Разрешаем любые VLESS Reality для создания резерва
MAX_PING_MS = 3000             # Расширяем лимит пинга до 3 секунд
MAX_SERVERS_IN_SUB = 40        # Оставляем топ-40 серверов
STRICT_US_ONLY = False

TCP_CONCURRENCY = 200
TCP_TIMEOUT = 2.0
MAX_CANDIDATES_FOR_XRAY = 400
XRAY_BATCH_SIZE = 40

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
    ".ru", "ozon", "yandex", "vk.com", "userapi", "wb.ru", "wildberries",
    "mail.ru", "kaspersky", "sber", "tinkoff", "gosuslugi", "avito",
    "kinopoisk", "megafon", "mts.ru", "beeline", "2gis", "rutube"
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
        return any(ipaddress.ip_address(ip_str) in net for net in CF_NETS)
    except Exception:
        return False

def safe_b64decode(data: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", data).replace("-", "+").replace("_", "/")
    cleaned += "=" * (len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def is_valid_reality_pbk(pbk: str) -> bool:
    if not pbk or len(pbk) not in (43, 44): return False
    cleaned = pbk.replace("-", "+").replace("_", "/")
    cleaned += "=" * (len(cleaned) % 4)
    try: return len(base64.b64decode(cleaned)) == 32
    except Exception: return False

def is_valid_domain_or_ip(val: str) -> bool:
    if not val or len(val) > 253 or " " in val: return False
    return bool(re.match(r"^[A-Za-z0-9.-]+$", val))

def guess_country_from_remark(remark: str) -> str:
    for marker, cc in COUNTRY_HINTS.items():
        if marker in remark: return cc
    return "EU"

def parse_stream_settings(params: dict, default_host: str) -> dict | None:
    net = params.get("type", ["tcp"])[0].lower()
    security = params.get("security", ["none"])[0].lower()
    stream = {"network": net, "security": security}

    if net == "tcp":
        if params.get("headerType", ["none"])[0] == "http":
            stream["tcpSettings"] = {"header": {"type": "http", "request": {"path": [params.get("path", ["/"])[0]], "headers": {"Host": [params.get("host", [default_host])[0]]}}}}
        else:
            stream["tcpSettings"] = {"header": {"type": "none"}}
    elif net == "ws" and security != "reality":
        stream["wsSettings"] = {"path": params.get("path", ["/"])[0], "headers": {"Host": params.get("host", [default_host])[0]}}
    elif net == "grpc":
        svc = params.get("serviceName", [""])[0]
        if not re.match(r"^[A-Za-z0-9_./-]*$", svc): return None
        stream["grpcSettings"] = {"serviceName": svc, "multiMode": params.get("mode", ["gun"])[0] == "multi"}
    elif net == "httpupgrade" and security != "reality":
        stream["httpupgradeSettings"] = {"path": params.get("path", ["/"])[0], "host": params.get("host", [default_host])[0]}
    else: return None

    if security == "tls":
        if params.get("allowInsecure", ["0"])[0] in ("1", "true") or params.get("insecure", ["0"])[0] in ("1", "true"): return None
        sni = params.get("sni", [params.get("host", [default_host])[0]])[0].strip()
        if not is_valid_domain_or_ip(sni): return None
        tls_cfg = {"serverName": sni, "fingerprint": params.get("fp", ["chrome"])[0].lower() if params.get("fp", ["chrome"])[0].lower() in VALID_FPS else "chrome"}
        if "alpn" in params and params["alpn"][0]:
            alpns = [a.strip() for a in params["alpn"][0].split(",") if a.strip() in VALID_ALPNS]
            if alpns: tls_cfg["alpn"] = alpns
        stream["tlsSettings"] = tls_cfg
    elif security == "reality":
        pbk = params.get("pbk", [""])[0].strip()
        sid = params.get("sid", [""])[0].strip()
        sni = params.get("sni", [""])[0].strip()
        if not is_valid_domain_or_ip(sni) or not is_valid_reality_pbk(pbk): return None
        if sid and (len(sid) > 16 or not HEX_RE.match(sid)): return None
        spx = params.get("spx", ["/"])[0].strip()
        stream["realitySettings"] = {
            "fingerprint": params.get("fp", ["firefox"])[0].lower() if params.get("fp", ["firefox"])[0].lower() in VALID_FPS else "firefox",
            "publicKey": pbk,
            "serverName": sni,
            "shortId": sid,
            "show": False,
            "spiderX": spx if spx.startswith("/") else "/",
        }
    elif security != "none": return None

    return stream

def parse_proxy_uri(uri: str, source_priority: int = 1) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vless://"):
            parsed = urlparse(uri)
            uuid, host, port = unquote(parsed.username or ""), parsed.hostname, parsed.port
            if not host or not is_valid_domain_or_ip(host) or not port or not (1 <= int(port) <= 65535) or not UUID_RE.match(uuid): return None
            remark = unquote(parsed.fragment)
            if any(bad in remark for bad in BAD_EXIT_REMARK_MARKERS): return None
            params = parse_qs(parsed.query)
            stream = parse_stream_settings(params, host)
            if not stream: return None
            flow = params.get("flow", [""])[0]
            if flow and (flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443") or stream["network"] != "tcp" or stream["security"] not in ("tls", "reality")): return None
            sni = params.get("sni", [""])[0].lower()
            is_reality = stream["security"] == "reality"
            has_ru_whitelist_sni = is_reality and any(m in sni for m in RU_WHITELIST_MARKERS)

            if STRICT_WL_RU and not has_ru_whitelist_sni: return None

            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": host, "port": int(port), "users": [{"encryption": "none", "flow": flow, "id": uuid, "level": 8, "security": "auto"}]}]},
                "streamSettings": stream,
            }
            return {
                "uri": uri, "proto": "vless", "host": host, "port": int(port),
                "is_reality": is_reality, "whitelist_sni": has_ru_whitelist_sni,
                "source_prio": source_priority, "key": f"vless:{host}:{port}:{uuid}", "remark": remark, "outbound": outbound,
            }
    except Exception: return None
    return None

def rename_uri(node: dict, new_remark: str) -> str:
    base_uri = node["uri"].split("#")[0]
    parsed = urlparse(base_uri)
    q = parse_qs(parsed.query, keep_blank_values=True)
    q.pop("allowInsecure", None)
    q.pop("insecure", None)
    return f"{urlunparse(parsed._replace(query=urlencode(q, doseq=True), fragment=''))}#{quote(new_remark)}"

async def fetch_sources() -> list[dict]:
    nodes = {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        for url in SOURCES:
            src_prio = 0 if any(k in url for k in ("whoahaow", "igareck", "LowiKLive", "VLESS-PO-GRIBI")) else 1
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = (await resp.read()).decode("utf-8", errors="ignore")
                        if "://" not in text[:300]: text = safe_b64decode(text)
                        for line in text.splitlines():
                            if line.strip().startswith("vless://"):
                                parsed = parse_proxy_uri(line.strip(), src_prio)
                                if parsed and parsed["key"] not in nodes: nodes[parsed["key"]] = parsed
            except Exception: pass
    return list(nodes.values())

async def check_tcp(node: dict, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(node["host"], node["port"])
            _, writer = await asyncio.wait_for(fut, timeout=TCP_TIMEOUT)
            node["ip"] = writer.get_extra_info("peername")[0] if writer.get_extra_info("peername") else node["host"]
            writer.close()
            await writer.wait_closed()
            node["tcp_ms"] = int((time.monotonic() - t0) * 1000)
            return node
        except Exception: return None

def prioritize_candidates(nodes: list[dict]) -> list[dict]:
    filtered = [n for n in nodes if not is_cloudflare_ip(n.get("ip", ""))]
    for n in filtered:
        cc = guess_country_from_remark(n["remark"])
        n["sort_key"] = (
            0 if n["whitelist_sni"] else 1,
            n["source_prio"],
            0 if n["is_reality"] else 1,
            0 if cc in ("US", "GB") else (1 if cc != "EU" else 2),
            n["tcp_ms"],
        )
    filtered.sort(key=lambda x: x["sort_key"])
    return filtered[:MAX_CANDIDATES_FOR_XRAY]

async def test_single_tunnel(node: dict, local_port: int, stats: dict) -> dict | None:
    proxy_addr = f"http://127.0.0.1:{local_port}"
    try:
        t0 = time.monotonic()
        proc_ping = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-x", proxy_addr, "--connect-timeout", "4", "--max-time", "6", "-w", "%{http_code}", "https://www.google.com/generate_204",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out_ping, _ = await asyncio.wait_for(proc_ping.communicate(), timeout=7)
        if out_ping.decode("utf-8", errors="ignore").strip() not in ("204", "200"): return None
        ping_ms = int((time.monotonic() - t0) * 1000)
        
        if ping_ms > MAX_PING_MS: return None

        proc_gem = await asyncio.create_subprocess_exec(
            "curl", "-sL", "-x", proxy_addr, "--connect-timeout", "4", "--max-time", "8", "-H", "Accept-Language: en-US,en;q=0.9", "-w", "\n__CURL_META__:%{http_code}|%{url_effective}", "https://gemini.google.com/",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out_gem, _ = await asyncio.wait_for(proc_gem.communicate(), timeout=9)
        raw_text = out_gem.decode("utf-8", errors="ignore")
        if "__CURL_META__:" not in raw_text: return None

        html_body, meta = raw_text.rsplit("__CURL_META__:", 1)
        code, url = meta.strip().split("|", 1)
        
        if code != "200" or any(b in url.lower() for b in ("/faq", "google.com/sorry", "policies.google.com", "support.google.com", "unsupported")): return None
        if '"45631641":false' in html_body or "[45631641,null,false" in html_body: return None
        
        loc_match = GOOGLE_LOC_RE.search(html_body)
        if loc_match and loc_match.group(1) in BLOCKED_ISO3: return None
        
        country = ISO3_TO_ISO2.get(loc_match.group(1), guess_country_from_remark(node["remark"])) if loc_match else guess_country_from_remark(node["remark"])
        node["exit_country"], node["gemini_ms"] = country, ping_ms
        return node
    except Exception: return None

async def run_xray_batch(batch: list[dict], base_port: int = 10000) -> list[dict]:
    current_batch = list(batch)
    while current_batch:
        inbounds, outbounds, rules = [], [], []
        for idx, node in enumerate(current_batch):
            inbounds.append({"tag": f"in_{idx}", "port": base_port + idx, "listen": "127.0.0.1", "protocol": "http", "settings": {"userLevel": 8}, "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True}})
            ob = dict(node["outbound"])
            ob["tag"] = f"out_{idx}"
            outbounds.append(ob)
            rules.append({"type": "field", "inboundTag": [f"in_{idx}"], "outboundTag": f"out_{idx}"})
        
        with open("xray_temp_config.json", "w", encoding="utf-8") as f:
            json.dump({"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": rules}}, f)
        
        proc = subprocess.Popen(["xray", "run", "-c", "xray_temp_config.json"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        await asyncio.sleep(0.6)
        
        if proc.poll() is None:
            stats = {"ok": 0}
            try:
                results = await asyncio.gather(*[test_single_tunnel(node, base_port + idx, stats) for idx, node in enumerate(current_batch)])
                return [r for r in results if r is not None]
            finally:
                proc.terminate()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: proc.kill()
        else:
            err_text = (proc.stdout.read() if proc.stdout else b"").decode("utf-8", errors="ignore")
            m = re.search(r"out_(\d+)", err_text)
            if m: current_batch.pop(int(m.group(1)))
            elif len(current_batch) > 1:
                mid = len(current_batch) // 2
                return await run_xray_batch(current_batch[:mid], base_port) + await run_xray_batch(current_batch[mid:], base_port + mid)
            else: return []
    return []

def flag_emoji(cc: str) -> str: return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397) if len(cc) == 2 and cc.isalpha() else "🌐"

async def main():
    nodes = await fetch_sources()
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    alive_nodes = [n for n in await asyncio.gather(*(check_tcp(n, sem) for n in nodes)) if n]
    candidates = prioritize_candidates(alive_nodes)
    
    working_nodes = []
    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        working_nodes.extend(await run_xray_batch(candidates[i:i + XRAY_BATCH_SIZE]))

    filtered_nodes = [n for n in working_nodes if n.get("gemini_ms", 9999) <= MAX_PING_MS]
    filtered_nodes.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if x["exit_country"] == "US" else (1 if x["exit_country"] in ("GB", "NL", "DE", "FI", "SE", "FR") else 2),
        x["gemini_ms"]
    ))

    final_uris = []
    for idx, n in enumerate(filtered_nodes[:MAX_SERVERS_IN_SUB], 1):
        cc, ms, wl = n["exit_country"], n["gemini_ms"], " | WL-RU" if n["whitelist_sni"] else ""
        final_uris.append(rename_uri(n, f"{flag_emoji(cc)} {cc} | Gemini OK | {ms}ms{wl} | VLESS #{idx}"))

    plain_text = "#profile-title: 🚀 Gemini VLESS Auto\n#profile-update-interval: 3\n" + "\n".join(final_uris)
    with open("sub.txt", "w", encoding="utf-8") as f: f.write(plain_text)
    with open("sub_base64.txt", "w", encoding="utf-8") as f: f.write(base64.b64encode(plain_text.encode("utf-8")).decode("utf-8"))

if __name__ == "__main__":
    asyncio.run(main())
