import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import os
import ipaddress
import logging
from tempfile import NamedTemporaryFile

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
    'https://stock.hostmonit.com/CloudFlareYes',
    'https://www.wetest.vip/page/cloudflare/address_v4.html'
]

# 用于初步匹配 IPv4 和 IPv6 的正则（宽松，最终靠 ipaddress 验证）
IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
# IPv6 匹配（简化版本，包含压缩形式和普通形式）
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b')

def create_session(retries=3, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504)):
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
        return str(ip_obj)  # 返回标准化（例如去掉前导零、压缩 IPv6）
    except ValueError:
        return None

def fetch_ips_from_url(session: requests.Session, url: str, timeout: float = 5.0) -> set[str]:
    result = set()
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code == 200 and resp.text:
            text = resp.text
            candidates = set()
            candidates.update(IPV4_RE.findall(text))
            candidates.update(IPV6_RE.findall(text))
            for cand in candidates:
                norm = normalize_and_validate_ip(cand)
                if norm:
                    result.add(norm)
        else:
            logging.warning("请求 %s 返回状态码 %s", url, resp.status_code)
    except requests.RequestException as e:
        logging.warning("请求 %s 失败: %s", url, e)
    return result

def sort_ips(ip_list: list[str]) -> list[str]:
    # 先按版本（4 在前，6 在后），再按数值
    def key_func(ip_str):
        ip_obj = ipaddress.ip_address(ip_str)
        version = ip_obj.version  # 4 或 6
        # 对于排序，把 IPv4 置 0，IPv6 置 1
        return (version, int(ip_obj))
    return sorted(ip_list, key=key_func)

def main():
    if os.path.exists('ip.txt'):
        try:
            os.remove('ip.txt')
        except OSError as e:
            logging.error("删除旧 ip.txt 失败: %s", e)

    session = create_session()
    unique_ips: set[str] = set()

    for url in URLS:
        logging.info("抓取 %s …", url)
        ips = fetch_ips_from_url(session, url)
        if ips:
            logging.info("从 %s 采集到 %d 个合法 IP", url, len(ips))
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
        logging.info("已保存 %d 个唯一 IP（包含 IPv4/IPv6）到 ip.txt。", len(sorted_ips))
    except Exception as e:
        logging.error("写入 ip.txt 失败: %s", e)
        if 'temp_name' in locals() and os.path.exists(temp_name):
            try:
                os.remove(temp_name)
            except OSError:
                pass

if __name__ == '__main__':
    main()
