import asyncio
import base64
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import warnings
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse, urlunparse
import aiohttp

warnings.filterwarnings("ignore")

# Источники серверов
SOURCES = [
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/vless.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
]

# Жесткий тайм-аут: ровно 5 минут на всю работу скрипта
GLOBAL_DEADLINE_SECONDS = 900
MAX_SERVERS_IN_SUB = 35
MAX_PING_MS = 3500

TCP_CONCURRENCY = 200
TCP_TIMEOUT = 1.5
MAX_CANDIDATES_FOR_XRAY = 250
XRAY_BATCH_SIZE = 15
BASE_LOCAL_PORT = 20000  # Исключаем конфликты с HAPP (10808/10809)

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
GOOGLE_LOC_RE = re.compile(r',2,1,200,"([A-Z]{3})"')

VALID_FPS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}
CF_NETS = [ipaddress.ip_network("104.16.0.0/12"), ipaddress.ip_network("172.64.0.0/13"), ipaddress.ip_network("162.158.0.0/15")]
RU_WHITELIST_MARKERS = (".ru", "ozon", "yandex", "vk.com", "userapi", "wb.ru", "wildberries", "mail.ru", "kaspersky", "sber", "gosuslugi")
BAD_EXIT_REMARK_MARKERS = ("🇷🇺", "| RUS", "Russia", "Россия", "Москва", "СПб", "🇧🇾", "🇨🇳", "🇮🇷")
BLOCKED_ISO3 = {"RUS", "BLR", "CHN", "HKG", "IRN", "PRK", "SYR"}

ISO3_TO_ISO2 = {
    "USA": "US", "GBR": "GB", "NLD": "NL", "DEU": "DE", "FIN": "FI",
    "SWE": "SE", "FRA": "FR", "POL": "PL", "EST": "EE", "LVA": "LV",
    "LTU": "LT", "CAN": "CA", "CHE": "CH", "AUT": "AT", "ESP": "ES",
    "ITA": "IT", "NOR": "NO", "DNK": "DK", "IRL": "IE", "CZE": "CZ",
    "SGP": "SG", "JPN": "JP", "KOR": "KR", "TUR": "TR", "KAZ": "KZ",
}

COUNTRY_HINTS = {
    "🇺🇸": "US", "USA": "US", "United States": "US", "| US": "US",
    "🇬🇧": "GB", "GBR": "GB", "UK": "GB", "英国": "GB",
    "🇳🇱": "NL", "NLD": "NL", "Netherlands": "NL", "| NL": "NL",
    "🇩🇪": "DE", "DEU": "DE", "Germany": "DE", "| DE": "DE",
    "🇫🇮": "FI", "FIN": "FI", "Finland": "FI",
    "🇸🇪": "SE", "SWE": "SE", "Sweden": "SE",
    "🇫🇷": "FR", "FRA": "FR", "France": "FR",
    "🇵🇱": "PL", "POL": "PL", "Poland": "PL",
}


def is_cloudflare_ip(ip_str: str) -> bool:
    try:
        return any(ipaddress.ip_address(ip_str) in net for net in CF_NETS)
    except Exception:
        return False


def safe_b64decode(data: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9+/=_-]", "", data).replace("-", "+").replace("_", "/")
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


def parse_proxy_uri(uri: str) -> dict | None:
    uri = uri.strip()
    try:
        if not uri.startswith("vless://"):
            return None
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
        sec = params.get("security", ["none"])[0].lower()
        if sec != "reality":
            return None

        pbk = params.get("pbk", [""])[0].strip()
        sni = params.get("sni", [host])[0].strip()
        if not is_valid_reality_pbk(pbk) or not is_valid_domain_or_ip(sni):
            return None

        flow = params.get("flow", [""])[0]
        if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
            flow = ""

        fp = params.get("fp", ["chrome"])[0].lower()
        if fp not in VALID_FPS:
            fp = "chrome"

        sid = params.get("sid", [""])[0].strip()
        spx = params.get("spx", ["/"])[0].strip()
        has_ru = any(m in sni.lower() for m in RU_WHITELIST_MARKERS)

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "flow": flow,
                        "encryption": "none",
                        "level": 8,
                    }],
                }]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "fingerprint": fp,
                    "serverName": sni,
                    "publicKey": pbk,
                    "shortId": sid,
                    "spiderX": spx if spx.startswith("/") else "/",
                },
                "tcpSettings": {"header": {"type": "none"}},
            },
        }

        return {
            "uri": uri,
            "host": host,
            "port": int(port),
            "whitelist_sni": has_ru,
            "key": f"vless:{host}:{port}:{uuid}",
            "remark": remark,
            "outbound": outbound,
        }
    except Exception:
        return None


def rename_uri(node: dict, new_remark: str) -> str:
    parsed = urlparse(node["uri"].split("#")[0])
    q = parse_qs(parsed.query, keep_blank_values=True)
    q.pop("allowInsecure", None)
    q.pop("insecure", None)
    return f"{urlunparse(parsed._replace(query=urlencode(q, doseq=True), fragment=''))}#{quote(new_remark)}"


def extract_vless_lines(raw_text: str) -> list[str]:
    lines = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("vless://"):
            lines.append(line)
        elif "://" not in line and len(line) > 60:
            decoded = safe_b64decode(line)
            if "vless://" in decoded:
                lines.extend(extract_vless_lines(decoded))
    return lines


async def fetch_sources() -> list[dict]:
    nodes = {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
        for url in SOURCES:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        content_bytes = await resp.read()
                        text = content_bytes.decode("utf-8", errors="ignore")
                        if "://" not in text[:400]:
                            text = safe_b64decode(text)
                        for line in extract_vless_lines(text):
                            parsed = parse_proxy_uri(line)
                            if parsed and parsed["key"] not in nodes:
                                nodes[parsed["key"]] = parsed
            except Exception:
                pass
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


def test_tunnel_curl(local_port: int) -> tuple[bool, int, str]:
    proxy_url = f"http://127.0.0.1:{local_port}"
    t0 = time.monotonic()

    # Шаг 1: Быстрый замер Google generate_204
    cmd_ping = [
        "curl.exe", "-s", "-o", "NUL",
        "-x", proxy_url,
        "--connect-timeout", "2.5",
        "--max-time", "4.0",
        "-w", "%{http_code}",
        "https://www.google.com/generate_204",
    ]
    try:
        res_ping = subprocess.run(cmd_ping, capture_output=True, text=True, timeout=5)
        if res_ping.stdout.strip() not in ("204", "200"):
            return False, 0, ""
    except Exception:
        return False, 0, ""

    ping_ms = int((time.monotonic() - t0) * 1000)
    if ping_ms > MAX_PING_MS:
        return False, 0, ""

    # Шаг 2: Проверка открытия Gemini
    cmd_gem = [
        "curl.exe", "-sL",
        "-x", proxy_url,
        "--connect-timeout", "2.5",
        "--max-time", "5.0",
        "-H", "Accept-Language: en-US,en;q=0.9",
        "-w", "\n__META__:%{http_code}|%{url_effective}",
        "https://gemini.google.com/",
    ]
    try:
        res_gem = subprocess.run(cmd_gem, capture_output=True, text=True, timeout=6)
        out = res_gem.stdout
        if "__META__:" not in out:
            return False, 0, ""

        body, meta = out.rsplit("__META__:", 1)
        code, final_url = meta.strip().split("|", 1)
        final_url_low = final_url.lower()

        if code != "200" or any(b in final_url_low for b in ("/faq", "sorry", "policies", "unsupported")):
            return False, 0, ""
        if '"45631641":false' in body or "[45631641,null,false" in body:
            return False, 0, ""

        loc_match = GOOGLE_LOC_RE.search(body)
        iso3 = loc_match.group(1) if loc_match else ""
        if iso3 in BLOCKED_ISO3:
            return False, 0, ""

        return True, ping_ms, ISO3_TO_ISO2.get(iso3, "")
    except Exception:
        return False, 0, ""


async def run_xray_batch(batch: list[dict], base_port: int, stop_event: asyncio.Event) -> list[dict]:
    if stop_event.is_set():
        return []

    inbounds, outbounds, rules = [], [], []
    for idx, node in enumerate(batch):
        port = base_port + idx
        inbounds.append({
            "tag": f"in_{idx}",
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "http",
            "settings": {"userLevel": 8},
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

    config_filename = f"xray_temp_{base_port}.json"
    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

    xray_exe = "xray.exe"
    if not os.path.exists(xray_exe):
        print("[!] xray.exe не найден в текущей папке!")
        return []

    proc = subprocess.Popen([xray_exe, "run", "-c", config_filename], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    await asyncio.sleep(0.7)

    passed_nodes = []
    if proc.poll() is None:
        try:
            loop = asyncio.get_running_loop()
            for idx, node in enumerate(batch):
                if stop_event.is_set():
                    break
                port = base_port + idx
                ok, ping_ms, country = await loop.run_in_executor(None, test_tunnel_curl, port)
                if ok:
                    node["gemini_ms"] = ping_ms
                    node["exit_country"] = country if country else guess_country_from_remark(node["remark"])
                    wl = " | WL-RU" if node["whitelist_sni"] else ""
                    print(f"  [+] НАЙДЕН РАБОЧИЙ ({ping_ms}ms{wl}): {node['host']} ({node['exit_country']})")
                    passed_nodes.append(node)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except Exception:
                proc.kill()
            if os.path.exists(config_filename):
                try:
                    os.remove(config_filename)
                except Exception:
                    pass
    else:
        # Если пачка упала из-за битого узла, пробуем по одиночке
        if os.path.exists(config_filename):
            try:
                os.remove(config_filename)
            except Exception:
                pass
        if len(batch) > 1 and not stop_event.is_set():
            mid = len(batch) // 2
            res1 = await run_xray_batch(batch[:mid], base_port, stop_event)
            res2 = await run_xray_batch(batch[mid:], base_port + mid, stop_event)
            return res1 + res2

    return passed_nodes


def flag_emoji(cc: str) -> str:
    return chr(ord(cc[0].upper()) + 127397) + chr(ord(cc[1].upper()) + 127397) if len(cc) == 2 and cc.isalpha() else "🌐"


async def timeout_watcher(stop_event: asyncio.Event, seconds: int):
    await asyncio.sleep(seconds)
    print(f"\n[!] Сработал лимит времени ({seconds // 60} мин). Завершаем сканирование и сохраняем все найденное...")
    stop_event.set()


async def main():
    start_time = time.time()
    stop_event = asyncio.Event()
    asyncio.create_task(timeout_watcher(stop_event, GLOBAL_DEADLINE_SECONDS))

    print("[*] 1. Сбор ключей из проверенных источников...")
    nodes = await fetch_sources()
    print(f"[+] Собрано уникальных Reality-серверов: {len(nodes)}")

    print("[*] 2. Быстрый TCP-пинг серверов через вашего провайдера...")
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    alive = [n for n in await asyncio.gather(*(check_tcp(n, sem) for n in nodes)) if n and not is_cloudflare_ip(n.get("ip", ""))]
    print(f"[+] Ответили по TCP: {len(alive)} серверов")

    # Приоритет: сначала серверы со SNI из белых списков РФ, затем США и Европа с наименьшим пингом
    alive.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if guess_country_from_remark(x["remark"]) in ("US", "GB") else 1,
        x["tcp_ms"],
    ))
    candidates = alive[:MAX_CANDIDATES_FOR_XRAY]

    print(f"[*] 3. Проверка кандидатов через Xray + нативный curl (таймаут: 5 минут)...")
    working_nodes = []

    for i in range(0, len(candidates), XRAY_BATCH_SIZE):
        if stop_event.is_set():
            break
        batch = candidates[i:i + XRAY_BATCH_SIZE]
        print(f"    Тестируется пачка {i + 1}..{i + len(batch)} (Найдено рабочих: {len(working_nodes)})...")
        passed = await run_xray_batch(batch, BASE_LOCAL_PORT, stop_event)
        working_nodes.extend(passed)

    # Сортировка результатов
    working_nodes.sort(key=lambda x: (
        0 if x["whitelist_sni"] else 1,
        0 if x["exit_country"] == "US" else (1 if x["exit_country"] in ("GB", "NL", "DE", "FI", "SE") else 2),
        x["gemini_ms"],
    ))

    top_nodes = working_nodes[:MAX_SERVERS_IN_SUB]
    final_uris = []
    for idx, n in enumerate(top_nodes, 1):
        cc, ms = n["exit_country"], n["gemini_ms"]
        wl = " | WL-RU" if n["whitelist_sni"] else ""
        final_uris.append(rename_uri(n, f"{flag_emoji(cc)} {cc} | Gemini OK | {ms}ms{wl} | #{idx}"))

    plain_text = "#profile-title: 🚀 Gemini VLESS Auto\n#profile-update-interval: 3\n" + "\n".join(final_uris)
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(plain_text)
    with open("sub_base64.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode(plain_text.encode("utf-8")).decode("utf-8"))

    elapsed = int(time.time() - start_time)
    print(f"\n[+] ГОТОВО за {elapsed} сек! Сохранено {len(final_uris)} рабочих серверов в sub.txt и sub_base64.txt")


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())