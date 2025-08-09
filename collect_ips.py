import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import os
import ipaddress
import logging
import time
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# 目标 URL 列表
URLS = [
    'https://ip.164746.xyz',
    'https://cf.090227.xyz',
    'https://ipdb.api.030101.xyz/?type=bestproxy&country=true',
    'https://vps789.com/cfip',
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://www.wetest.vip/page/cloudflare/address_v4.html'
]

# 正则初筛 IPv4 和 IPv6
IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b')

# 每个站点最多采集多少个（IPv4+IPv6 混合）
MAX_PER_SITE = 30

def create_session(retries=2, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET"],
        raise_on_status=False,
        raise_on_redirect=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; IP-Scraper/1.0; +https://example.com)"
    })
    return session

def normalize_and_validate_ip(raw: str):
    try:
        ip_obj = ipaddress.ip_address(raw.strip())
        return str(ip_obj)  # 标准化字符串形式
    except ValueError:
        return None

def fetch_ips_from_url(session: requests.Session, url: str, last_request_times: dict, timeout: float = 5.0) -> set[str]:
    collected = set()
    parsed = urlparse(url)
    domain = parsed.netloc

    # 同域名节流（可选：防止短时间内重复打扰）
    now = time.monotonic()
    if domain in last_request_times:
        elapsed = now - last_request_times[domain]
        if elapsed < 0.5:  # 每个域名最小间隔 0.5 秒
            time.sleep(0.5 - elapsed)
    last_request_times[domain] = time.monotonic()

    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code == 200 and resp.text:
            text = resp.text
            # 初筛候选
            candidates = []
            candidates.extend(IPV4_RE.findall(text))
            candidates.extend(IPV6_RE.findall(text))
            seen_this_site = set()
            for cand in candidates:
                if len(collected) >= MAX_PER_SITE:
                    break
                norm = normalize_and_validate_ip(cand)
                if not norm:
                    continue
                if norm in seen_this_site:
                    continue  # 本站点内重复
                seen_this_site.add(norm)
                collected.add(norm)
        else:
            logging.warning("请求 %s 返回状态码 %s", url, resp.status_code)
    except requests.RequestException as e:
        logging.warning("请求 %s 失败: %s", url, e)
    return collected

def sort_ips(ip_list: list[str]) -> list[str]:
    def key_func(ip_str):
        ip_obj = ipaddress.ip_address(ip_str)
        # IPv4 先于 IPv6，内部按整数值
        return (ip_obj.version, int(ip_obj))
    return sorted(ip_list, key=key_func)

def main():
    if os.path.exists('ip.txt'):
        try:
            os.remove('ip.txt')
        except OSError as e:
            logging.error("删除旧 ip.txt 失败: %s", e)

    session = create_session()
    unique_ips: set[str] = set()
    last_request_times: dict[str, float] = {}

    for url in URLS:
        logging.info("开始从 %s 抓取（最多 %d 个）…", url, MAX_PER_SITE)
        ips = fetch_ips_from_url(session, url, last_request_times)
        logging.info("从 %s 获取到 %d 个 IP", url, len(ips))
        unique_ips.update(ips)

    if not unique_ips:
        logging.info("未找到任何合法的 IP 地址。")
        return

    sorted_ips = sort_ips(list(unique_ips))

    try:
        with NamedTemporaryFile('w', delete=False, encoding='utf-8', newline='\n') as tmp:
            for ip in sorted_ips:
                tmp.write(ip + '\n')
            temp_name = tmp.name
        os.replace(temp_name, 'ip.txt')
        logging.info("已保存 %d 个唯一 IP（IPv4/IPv6 混合）到 ip.txt。", len(sorted_ips))
    except Exception as e:
        logging.error("写入 ip.txt 失败: %s", e)
        if 'temp_name' in locals() and os.path.exists(temp_name):
            try:
                os.remove(temp_name)
            except OSError:
                pass

if __name__ == '__main__':
    main()
