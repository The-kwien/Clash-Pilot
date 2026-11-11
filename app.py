#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clash Pilot - a local, Clash-compatible network control panel.

The application is intentionally dependency-light:
  * Python standard library for the HTTP server and all desktop integration
  * PyYAML for Clash / Mihomo configuration files
  * A real Mihomo (or Clash.Meta) core when one is configured
  * A fully interactive built-in demo runtime when no core is present

Run:  python app.py
Open: http://127.0.0.1:8787
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import ctypes
import hashlib
import ipaddress
import json
import math
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
import webbrowser
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - handled at startup
    yaml = None

APP_NAME = "Clash Pilot"
APP_VERSION = "1.0.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
PROFILE_DIR = DATA_DIR / "profiles"
RUNTIME_DIR = DATA_DIR / "runtime"
ICON_DIR = DATA_DIR / "icons"
STATE_FILE = DATA_DIR / "state.json"
STATS_FILE = DATA_DIR / "stats.json"
HISTORY_FILE = DATA_DIR / "connection-history.json"
PROXY_BACKUP_FILE = DATA_DIR / "system-proxy-backup.json"
DEFAULT_UI_PORT = 8787
MAX_BODY_BYTES = 12 * 1024 * 1024

PROXY_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
DEFAULT_BYPASS = (
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;"
    "172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;"
    "172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"
)

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "GEOIP",
    "GEOSITE",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "SRC-IP-CIDR6",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "RULE-SET",
    "SUB-RULE",
    "NETWORK",
    "MATCH",
}

COUNTRY_MAP = [
    (("香港", "hong kong", "hongkong", "hk"), "🇭🇰", "香港", "HK"),
    (("台湾", "台灣", "taiwan", "tw"), "🇹🇼", "台湾", "TW"),
    (("日本", "东京", "東京", "大阪", "japan", "tokyo", "osaka", "jp"), "🇯🇵", "日本", "JP"),
    (("新加坡", "狮城", "singapore", "sg"), "🇸🇬", "新加坡", "SG"),
    (("美国", "美國", "洛杉矶", "西雅图", "硅谷", "united states", "usa", "us "), "🇺🇸", "美国", "US"),
    (("韩国", "韓國", "首尔", "korea", "seoul", "kr"), "🇰🇷", "韩国", "KR"),
    (("德国", "德國", "法兰克福", "germany", "frankfurt", "de"), "🇩🇪", "德国", "DE"),
    (("英国", "英國", "伦敦", "united kingdom", "london", "uk", "gb"), "🇬🇧", "英国", "GB"),
    (("澳大利亚", "澳洲", "悉尼", "australia", "sydney", "au"), "🇦🇺", "澳大利亚", "AU"),
    (("加拿大", "多伦多", "canada", "toronto", "ca"), "🇨🇦", "加拿大", "CA"),
    (("法国", "法國", "巴黎", "france", "paris", "fr"), "🇫🇷", "法国", "FR"),
    (("荷兰", "荷蘭", "阿姆斯特丹", "netherlands", "amsterdam", "nl"), "🇳🇱", "荷兰", "NL"),
    (("俄罗斯", "俄羅斯", "russia", "ru"), "🇷🇺", "俄罗斯", "RU"),
    (("印度", "india", "in "), "🇮🇳", "印度", "IN"),
    (("巴西", "brazil", "br"), "🇧🇷", "巴西", "BR"),
    (("土耳其", "turkey", "tr"), "🇹🇷", "土耳其", "TR"),
    (("越南", "vietnam", "vn"), "🇻🇳", "越南", "VN"),
    (("泰国", "泰國", "thailand", "th"), "🇹🇭", "泰国", "TH"),
    (("马来西亚", "馬來西亞", "malaysia", "my"), "🇲🇾", "马来西亚", "MY"),
    (("菲律宾", "philippines", "ph"), "🇵🇭", "菲律宾", "PH"),
    (("阿根廷", "argentina", "ar"), "🇦🇷", "阿根廷", "AR"),
    (("瑞士", "switzerland", "ch"), "🇨🇭", "瑞士", "CH"),
    (("瑞典", "sweden", "se"), "🇸🇪", "瑞典", "SE"),
    (("挪威", "norway", "no"), "🇳🇴", "挪威", "NO"),
    (("芬兰", "finland", "fi"), "🇫🇮", "芬兰", "FI"),
    (("波兰", "poland", "pl"), "🇵🇱", "波兰", "PL"),
]

REGIONAL_FLAG_RE = re.compile(
    "[\U0001F1E6-\U0001F1FF]{2}"
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def today_str() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d")


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return copy.deepcopy(default)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(value, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def deep_merge(base: dict, incoming: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (incoming or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def now_epoch() -> float:
    return time.time()


def clean_name(value: str, fallback: str = "未命名配置") -> str:
    value = re.sub(r"\s+", " ", (value or "").strip())
    return value[:80] or fallback


def guess_country(name: str) -> tuple[str, str, str]:
    """Return (flag, country label, ISO code) inferred from a node name."""
    m = REGIONAL_FLAG_RE.search(name or "")
    if m:
        flag = m.group(0)
        # Reverse lookup for a friendly Chinese label where possible.
        for needles, _flag, label, code in COUNTRY_MAP:
            if flag == _flag:
                return flag, label, code
        return flag, "地区节点", ""
    lower = (name or "").lower()
    for needles, flag, label, code in COUNTRY_MAP:
        for needle in needles:
            if needle in lower:
                return flag, label, code
    return "🌐", "全球", ""


def strip_flag(name: str) -> str:
    result = REGIONAL_FLAG_RE.sub("", name or "").strip()
    result = re.sub(r"^[\s|·•\-]+", "", result)
    return result or (name or "未命名节点")


def protocol_label(kind: str) -> str:
    value = (kind or "proxy").lower()
    mapping = {
        "shadowsocks": "SS",
        "shadowsocksr": "SSR",
        "vmess": "VMess",
        "vless": "VLESS",
        "trojan": "Trojan",
        "hysteria": "Hy",
        "hysteria2": "Hy2",
        "tuic": "TUIC",
        "wireguard": "WG",
        "snell": "Snell",
        "http": "HTTP",
        "socks5": "SOCKS",
        "ss": "SS",
        "selector": "策略组",
        "urltest": "自动",
        "fallback": "故障转移",
        "loadbalance": "负载均衡",
        "relay": "链式",
        "direct": "直连",
        "reject": "拦截",
        "compatible": "兼容",
    }
    return mapping.get(value, kind or "Proxy")


def normalize_group_type(value: str) -> str:
    value = (value or "").lower()
    if value in ("selector", "select"):
        return "select"
    if value in ("urltest", "url-test"):
        return "url-test"
    if value == "fallback":
        return "fallback"
    if value in ("loadbalance", "load-balance"):
        return "load-balance"
    if value == "relay":
        return "relay"
    return value or "select"


def parse_rule(raw: str, index: int) -> dict:
    parts = [part.strip() for part in str(raw).split(",")]
    rtype = (parts[0] if parts else "MATCH").upper()
    if rtype == "MATCH":
        payload = ""
        target = parts[1] if len(parts) > 1 else "DIRECT"
        options = parts[2:]
    else:
        payload = parts[1] if len(parts) > 1 else ""
        target = parts[2] if len(parts) > 2 else "DIRECT"
        options = parts[3:]
    options = [opt for opt in options if opt]
    return {
        "index": index,
        "raw": str(raw),
        "type": rtype,
        "payload": payload,
        "target": target,
        "options": options,
        "noResolve": any(opt.lower() == "no-resolve" for opt in options),
    }


def format_rule(rule: dict) -> str:
    parts = [rule["type"]]
    if rule["type"] != "MATCH":
        parts.append(rule.get("payload", ""))
    parts.append(rule.get("target", "DIRECT"))
    parts.extend(rule.get("options") or [])
    return ",".join(parts)


def prefer_https_test_url(url: str) -> str:
    """Upgrade common HTTP health-check URLs to HTTPS.

    Some subscription groups still use http://www.gstatic.com/generate_204.
    Mihomo explicitly warns that HTTP health checks are unreliable because a
    provider may hijack the test address or reject repeated HEAD requests.
    """
    value = str(url or "").strip()
    if not value.lower().startswith("http://"):
        return value
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return value
    host = (parsed.hostname or "").lower()
    test_hosts = {
        "www.gstatic.com",
        "connectivitycheck.gstatic.com",
        "www.google.com",
        "cp.cloudflare.com",
        "www.cloudflare.com",
    }
    if host in test_hosts and ("generate_204" in parsed.path or parsed.path in ("", "/")):
        return urllib.parse.urlunparse(parsed._replace(scheme="https"))
    return value


def parse_subscription_userinfo(value: str | None) -> dict | None:
    if not value:
        return None
    result: dict[str, int] = {}
    for part in value.split(";"):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        key = key.strip().lower()
        try:
            result[key] = int(raw.strip())
        except ValueError:
            continue
    if not result:
        return None
    return {
        "upload": result.get("upload", 0),
        "download": result.get("download", 0),
        "total": result.get("total", 0),
        "expire": result.get("expire", 0),
    }


def possible_base64_yaml(text: str) -> str:
    """Some subscription services return base64 instead of Clash YAML."""
    stripped = re.sub(r"\s+", "", text or "")
    if len(stripped) < 40 or "proxies:" in text or "proxy-groups:" in text:
        return text
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return text
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=False)
        candidate = decoded.decode("utf-8-sig")
        if "proxies:" in candidate or "proxy-groups:" in candidate:
            return candidate
    except (ValueError, UnicodeDecodeError):
        pass
    return text


# ---------------------------------------------------------------------------
# Built-in demo configuration
# ---------------------------------------------------------------------------

DEMO_YAML = """\
# Clash Pilot demo profile. All values are simulated.
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false

profile:
  name: Aurora Demo

dns:
  enable: true
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - 223.5.5.5
    - 119.29.29.29

proxies:
  - name: "🇭🇰 香港 IEPL 01"
    type: ss
    server: hk1.aurora-demo.net
    port: 443
    cipher: aes-256-gcm
    password: demo
  - name: "🇭🇰 香港 IEPL 02"
    type: ss
    server: hk2.aurora-demo.net
    port: 443
    cipher: aes-256-gcm
    password: demo
  - name: "🇯🇵 日本 东京 01"
    type: vmess
    server: jp1.aurora-demo.net
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    alterId: 0
    cipher: auto
    tls: true
  - name: "🇯🇵 日本 大阪 02"
    type: vmess
    server: jp2.aurora-demo.net
    port: 443
    uuid: 00000000-0000-0000-0000-000000000002
    alterId: 0
    cipher: auto
    tls: true
  - name: "🇸🇬 新加坡 01"
    type: trojan
    server: sg1.aurora-demo.net
    port: 443
    password: demo
    sni: sg1.aurora-demo.net
  - name: "🇺🇸 美国 洛杉矶 01"
    type: vmess
    server: us1.aurora-demo.net
    port: 443
    uuid: 00000000-0000-0000-0000-000000000003
    alterId: 0
    cipher: auto
    tls: true
  - name: "🇺🇸 美国 西雅图 02"
    type: hysteria2
    server: us2.aurora-demo.net
    port: 8443
    password: demo
    sni: us2.aurora-demo.net
  - name: "🇹🇼 台湾 台北 01"
    type: ss
    server: tw1.aurora-demo.net
    port: 443
    cipher: aes-256-gcm
    password: demo
  - name: "🇰🇷 韩国 首尔 01"
    type: trojan
    server: kr1.aurora-demo.net
    port: 443
    password: demo
    sni: kr1.aurora-demo.net
  - name: "🇩🇪 德国 法兰克福 01"
    type: vmess
    server: de1.aurora-demo.net
    port: 443
    uuid: 00000000-0000-0000-0000-000000000004
    alterId: 0
    cipher: auto
    tls: true
  - name: "🇬🇧 英国 伦敦 01"
    type: hysteria2
    server: uk1.aurora-demo.net
    port: 8443
    password: demo
    sni: uk1.aurora-demo.net
  - name: "🇦🇺 澳大利亚 悉尼 01"
    type: ss
    server: au1.aurora-demo.net
    port: 443
    cipher: aes-256-gcm
    password: demo

proxy-groups:
  - name: "🚀 节点选择"
    type: select
    proxies:
      - "♻️ 自动选择"
      - "🇭🇰 香港 IEPL 01"
      - "🇭🇰 香港 IEPL 02"
      - "🇯🇵 日本 东京 01"
      - "🇯🇵 日本 大阪 02"
      - "🇸🇬 新加坡 01"
      - "🇺🇸 美国 洛杉矶 01"
      - "🇺🇸 美国 西雅图 02"
      - "🇹🇼 台湾 台北 01"
      - "🇰🇷 韩国 首尔 01"
      - "🇩🇪 德国 法兰克福 01"
      - "🇬🇧 英国 伦敦 01"
      - "🇦🇺 澳大利亚 悉尼 01"
      - "DIRECT"
  - name: "♻️ 自动选择"
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
      - "🇭🇰 香港 IEPL 01"
      - "🇭🇰 香港 IEPL 02"
      - "🇯🇵 日本 东京 01"
      - "🇯🇵 日本 大阪 02"
      - "🇸🇬 新加坡 01"
      - "🇺🇸 美国 洛杉矶 01"
      - "🇺🇸 美国 西雅图 02"
      - "🇹🇼 台湾 台北 01"
      - "🇰🇷 韩国 首尔 01"
  - name: "🌍 国际互联"
    type: select
    proxies:
      - "🚀 节点选择"
      - "🇭🇰 香港 IEPL 01"
      - "🇯🇵 日本 东京 01"
      - "🇸🇬 新加坡 01"
      - "🇺🇸 美国 洛杉矶 01"
      - "🇩🇪 德国 法兰克福 01"
      - "🇬🇧 英国 伦敦 01"
      - "DIRECT"
  - name: "🎬 流媒体"
    type: select
    proxies:
      - "🇭🇰 香港 IEPL 01"
      - "🇯🇵 日本 东京 01"
      - "🇸🇬 新加坡 01"
      - "🇺🇸 美国 洛杉矶 01"
      - "🚀 节点选择"
      - "DIRECT"
  - name: "🤖 人工智能"
    type: select
    proxies:
      - "🇺🇸 美国 洛杉矶 01"
      - "🇯🇵 日本 东京 01"
      - "🇸🇬 新加坡 01"
      - "🇭🇰 香港 IEPL 01"
      - "🚀 节点选择"
  - name: "🎮 游戏平台"
    type: select
    proxies:
      - "🇯🇵 日本 大阪 02"
      - "🇭🇰 香港 IEPL 02"
      - "🇰🇷 韩国 首尔 01"
      - "🇺🇸 美国 西雅图 02"
      - "DIRECT"
  - name: "📲 国内直连"
    type: select
    proxies:
      - "DIRECT"
      - "🚀 节点选择"
  - name: "🛑 广告拦截"
    type: select
    proxies:
      - "REJECT"
      - "DIRECT"
  - name: "🐟 漏网之鱼"
    type: select
    proxies:
      - "🚀 节点选择"
      - "DIRECT"

rules:
  - "DOMAIN-SUFFIX,openai.com,🤖 人工智能"
  - "DOMAIN-SUFFIX,anthropic.com,🤖 人工智能"
  - "DOMAIN-SUFFIX,claude.ai,🤖 人工智能"
  - "DOMAIN-SUFFIX,gemini.google.com,🤖 人工智能"
  - "DOMAIN-SUFFIX,github.com,🌍 国际互联"
  - "DOMAIN-SUFFIX,githubusercontent.com,🌍 国际互联"
  - "DOMAIN-SUFFIX,netflix.com,🎬 流媒体"
  - "DOMAIN-SUFFIX,youtube.com,🎬 流媒体"
  - "DOMAIN-SUFFIX,disneyplus.com,🎬 流媒体"
  - "DOMAIN-SUFFIX,spotify.com,🎬 流媒体"
  - "DOMAIN-SUFFIX,steampowered.com,🎮 游戏平台"
  - "DOMAIN-SUFFIX,epicgames.com,🎮 游戏平台"
  - "DOMAIN-KEYWORD,google,🌍 国际互联"
  - "DOMAIN-SUFFIX,adservice.google.com,🛑 广告拦截"
  - "DOMAIN-KEYWORD,doubleclick,🛑 广告拦截"
  - "DOMAIN-SUFFIX,baidu.com,📲 国内直连"
  - "DOMAIN-SUFFIX,qq.com,📲 国内直连"
  - "DOMAIN-SUFFIX,bilibili.com,📲 国内直连"
  - "DOMAIN-SUFFIX,taobao.com,📲 国内直连"
  - "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
  - "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve"
  - "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"
  - "GEOIP,CN,📲 国内直连"
  - "MATCH,🐟 漏网之鱼"
"""


DEFAULT_STATE = {
    "version": 1,
    "settings": {
        "engineMode": "demo",  # demo | auto | core
        "autoStart": True,
        "corePath": "",
        "mixedPort": 7890,
        "controllerPort": 9090,
        "secret": "clash-pilot",
        "allowLan": False,
        "ipv6": False,
        "mode": "rule",
        "systemProxy": False,
        "bypass": DEFAULT_BYPASS,
        "theme": "dark",
        "accent": "violet",
        "textScale": 1.0,
    },
    "profiles": [],
    "activeProfileId": "",
    "selections": {},
    "blocked": [],
    "routeOverrides": [],
}


# ---------------------------------------------------------------------------
# Profile storage
# ---------------------------------------------------------------------------


class Store:
    def __init__(self) -> None:
        if yaml is None:
            raise RuntimeError("缺少 PyYAML，请先运行：python -m pip install pyyaml")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        ICON_DIR.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.state = self._load_state()
        self._ensure_profiles()

    def _load_state(self) -> dict:
        raw = read_json(STATE_FILE, {})
        state = deep_merge(DEFAULT_STATE, raw if isinstance(raw, dict) else {})
        if not isinstance(state.get("profiles"), list):
            state["profiles"] = []
        if not isinstance(state.get("selections"), dict):
            state["selections"] = {}
        if not isinstance(state.get("blocked"), list):
            state["blocked"] = []
        if not isinstance(state.get("routeOverrides"), list):
            state["routeOverrides"] = []
        try:
            state["settings"]["textScale"] = float(state["settings"].get("textScale", 1.0))
        except (TypeError, ValueError):
            state["settings"]["textScale"] = 1.0
        return state

    def save(self) -> None:
        with self.lock:
            write_json(STATE_FILE, self.state)

    def _ensure_profiles(self) -> None:
        with self.lock:
            valid: list[dict] = []
            for item in self.state.get("profiles", []):
                if not isinstance(item, dict) or not item.get("id"):
                    continue
                path = self.profile_path(item["id"])
                if path.exists():
                    item.setdefault("counts", {"proxies": 0, "groups": 0, "rules": 0})
                    valid.append(item)
            self.state["profiles"] = valid

            if not valid:
                self._create_initial_demo_locked()
            else:
                active = self.state.get("activeProfileId")
                if not any(p["id"] == active for p in valid):
                    self.state["activeProfileId"] = valid[0]["id"]
                self.save()

    def _create_initial_demo_locked(self) -> None:
        profile_id = "demo"
        path = self.profile_path(profile_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEMO_YAML, encoding="utf-8")
        data = yaml.safe_load(DEMO_YAML) or {}
        meta = {
            "id": profile_id,
            "name": "Aurora Demo",
            "type": "builtin",
            "url": "",
            "createdAt": now_iso(),
            "updatedAt": now_iso(),
            "builtin": True,
            "remote": False,
            "counts": {
                "proxies": len(data.get("proxies") or []),
                "groups": len(data.get("proxy-groups") or []),
                "rules": len(data.get("rules") or []),
            },
            "subscription": None,
        }
        self.state["profiles"] = [meta]
        self.state["activeProfileId"] = profile_id
        self.state["selections"] = {
            profile_id: {
                "🚀 节点选择": "🇭🇰 香港 IEPL 01",
                "🌍 国际互联": "🚀 节点选择",
                "🎬 流媒体": "🇭🇰 香港 IEPL 01",
                "🤖 人工智能": "🇺🇸 美国 洛杉矶 01",
                "🎮 游戏平台": "🇯🇵 日本 大阪 02",
                "📲 国内直连": "DIRECT",
                "🛑 广告拦截": "REJECT",
                "🐟 漏网之鱼": "🚀 节点选择",
            }
        }
        self.save()

    def profile_path(self, profile_id: str) -> Path:
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", profile_id or "")
        return PROFILE_DIR / f"{safe_id}.yaml"

    def get_profile(self, profile_id: str | None = None) -> dict | None:
        with self.lock:
            target = profile_id or self.state.get("activeProfileId")
            for item in self.state["profiles"]:
                if item["id"] == target:
                    return copy.deepcopy(item)
        return None

    def read_profile(self, profile_id: str) -> str:
        path = self.profile_path(profile_id)
        if not path.exists():
            raise ValueError("配置文件不存在")
        return path.read_text(encoding="utf-8-sig")

    def write_profile(self, profile_id: str, content: str) -> None:
        path = self.profile_path(profile_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".yaml.tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, path)

    def parse(self, content: str) -> tuple[dict, dict]:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            location = f"（第 {mark.line + 1} 行）" if mark else ""
            raise ValueError(f"YAML 解析失败{location}") from exc
        if not isinstance(data, dict):
            raise ValueError("配置内容不是有效的 Clash YAML")
        proxies = data.get("proxies") or []
        groups = data.get("proxy-groups") or []
        rules = data.get("rules") or []
        providers = data.get("proxy-providers") or {}
        if not isinstance(proxies, list) or not isinstance(groups, list) or not isinstance(rules, list):
            raise ValueError("配置中的 proxies / proxy-groups / rules 格式不正确")
        if not proxies and not providers:
            raise ValueError("未在配置中找到代理节点（proxies）")
        counts = {"proxies": len(proxies), "groups": len(groups), "rules": len(rules)}
        return data, counts

    def create_profile(
        self,
        content: str,
        name: str = "",
        url: str = "",
        remote: bool = False,
        subscription: dict | None = None,
    ) -> dict:
        data, counts = self.parse(content)
        profile_name = clean_name(
            name
            or ((data.get("profile") or {}).get("name") if isinstance(data.get("profile"), dict) else "")
            or (urllib.parse.urlparse(url).hostname if url else "")
            or "导入配置"
        )
        with self.lock:
            existing = {p["name"] for p in self.state["profiles"]}
            base_name = profile_name
            suffix = 2
            while profile_name in existing:
                profile_name = f"{base_name} ({suffix})"
                suffix += 1
            profile_id = uuid.uuid4().hex[:12]
            meta = {
                "id": profile_id,
                "name": profile_name,
                "type": "remote" if remote else "local",
                "url": url,
                "createdAt": now_iso(),
                "updatedAt": now_iso(),
                "builtin": False,
                "remote": remote,
                "counts": counts,
                "subscription": subscription,
            }
            self.write_profile(profile_id, content)
            self.state["profiles"].append(meta)
            self.state.setdefault("selections", {})[profile_id] = {}
            if not self.state.get("activeProfileId") or len(self.state["profiles"]) == 1:
                self.state["activeProfileId"] = profile_id
            self.save()
            return copy.deepcopy(meta)

    def update_profile_meta(self, profile_id: str, **updates: Any) -> dict | None:
        with self.lock:
            for item in self.state["profiles"]:
                if item["id"] == profile_id:
                    item.update(updates)
                    item["updatedAt"] = updates.get("updatedAt") or now_iso()
                    self.save()
                    return copy.deepcopy(item)
        return None

    def delete_profile(self, profile_id: str) -> None:
        with self.lock:
            profile = next((p for p in self.state["profiles"] if p["id"] == profile_id), None)
            if not profile:
                raise ValueError("配置不存在")
            if len(self.state["profiles"]) <= 1:
                raise ValueError("至少需要保留一个配置")
            self.state["profiles"] = [p for p in self.state["profiles"] if p["id"] != profile_id]
            self.state.get("selections", {}).pop(profile_id, None)
            if self.state.get("activeProfileId") == profile_id:
                self.state["activeProfileId"] = self.state["profiles"][0]["id"]
            self.save()
            try:
                self.profile_path(profile_id).unlink(missing_ok=True)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Demo runtime
# ---------------------------------------------------------------------------


DEMO_TEMPLATES = [
    ("www.google.com", 443, "TCP", "DOMAIN-KEYWORD(google)", "🌍 国际互联", "chrome.exe"),
    ("api.openai.com", 443, "TCP", "DOMAIN-SUFFIX(openai.com)", "🤖 人工智能", "ChatGPT.exe"),
    ("api.anthropic.com", 443, "TCP", "DOMAIN-SUFFIX(anthropic.com)", "🤖 人工智能", "chrome.exe"),
    ("www.youtube.com", 443, "TCP", "DOMAIN-SUFFIX(youtube.com)", "🎬 流媒体", "chrome.exe"),
    ("github.com", 443, "TCP", "DOMAIN-SUFFIX(github.com)", "🌍 国际互联", "Code.exe"),
    ("api.github.com", 443, "TCP", "DOMAIN-SUFFIX(github.com)", "🌍 国际互联", "Code.exe"),
    ("www.netflix.com", 443, "TCP", "DOMAIN-SUFFIX(netflix.com)", "🎬 流媒体", "msedge.exe"),
    ("steamcdn-a.akamaihd.net", 443, "TCP", "DOMAIN-SUFFIX,steampowered.com", "🎮 游戏平台", "steam.exe"),
    ("www.bilibili.com", 443, "TCP", "DOMAIN-SUFFIX(bilibili.com)", "📲 国内直连", "chrome.exe"),
    ("upos-sz-mirrorcos.bilivideo.com", 443, "TCP", "DOMAIN-SUFFIX(bilivideo.com)", "📲 国内直连", "chrome.exe"),
    ("www.baidu.com", 443, "TCP", "DOMAIN-SUFFIX(baidu.com)", "📲 国内直连", "chrome.exe"),
    ("api.spotify.com", 443, "TCP", "DOMAIN-SUFFIX(spotify.com)", "🎬 流媒体", "Spotify.exe"),
    ("claude.ai", 443, "TCP", "DOMAIN-SUFFIX(claude.ai)", "🤖 人工智能", "chrome.exe"),
    ("www.figma.com", 443, "TCP", "DOMAIN-SUFFIX(figma.com)", "🌍 国际互联", "chrome.exe"),
    ("discord.com", 443, "TCP", "DOMAIN-SUFFIX(discord.com)", "🌍 国际互联", "Discord.exe"),
    ("1.1.1.1", 53, "UDP", "GEOIP,CN", "🚀 节点选择", "svchost.exe"),
    ("store.steampowered.com", 443, "TCP", "DOMAIN-SUFFIX(steampowered.com)", "🎮 游戏平台", "steam.exe"),
    ("i.ytimg.com", 443, "TCP", "DOMAIN-SUFFIX(youtube.com)", "🎬 流媒体", "chrome.exe"),
    ("registry.npmjs.org", 443, "TCP", "DOMAIN-SUFFIX,npmjs.org", "🌍 国际互联", "node.exe"),
    ("t.me", 443, "TCP", "DOMAIN-SUFFIX(t.me)", "🚀 节点选择", "Telegram.exe"),
]

DEMO_LOG_MESSAGES = [
    "[TCP] {src} --> {host}:{port} match {rule} using {chain}",
    "[TCP] {src} --> {host}:{port} match {rule} using {chain}",
    "[UDP] {src} --> {host}:{port} match {rule} using {chain}",
    "inbound connection from 127.0.0.1 accepted",
    "DNS query {host} resolved to 198.18.{a}.{b}",
    "health check {node}: {delay}ms",
]


class DemoRuntime:
    def __init__(self, manager: "Manager") -> None:
        self.manager = manager
        self.lock = threading.RLock()
        self.running = False
        self.started_at: float | None = None
        self.connections: dict[str, dict] = {}
        self.phase = random.random() * 8
        self._last_connection_emit = 0.0
        self._last_log_emit = 0.0

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        with self.lock:
            if self.running:
                return
            self.running = True
            self.started_at = time.time()
            self.connections.clear()
            for _ in range(random.randint(7, 12)):
                self._add_connection()
            self.manager.log("info", "内置演示内核已启动，当前展示的是模拟网络数据")
            self.manager.log("info", "混合端口 127.0.0.1:%s · 规则模式已加载" % self.manager.store.state["settings"]["mixedPort"])
            self.manager.log("info", "DNS 已初始化 · fake-ip 198.18.0.1/16")
            self.manager.log("info", "演示订阅 Aurora Demo 已激活 · 12 个节点")
        self.manager.seed_history_if_needed()

    def stop(self) -> None:
        with self.lock:
            if not self.running:
                return
            self.running = False
            self.connections.clear()
            self.started_at = None
        self.manager.log("info", "内置演示内核已停止")

    # -- simulation --------------------------------------------------------
    def _node_for_group(self, group_name: str) -> str:
        try:
            data, _ = self.manager.get_profile_data()
        except Exception:
            return "DIRECT"
        groups = {g.get("name"): g for g in data.get("proxy-groups") or [] if isinstance(g, dict)}
        group = groups.get(group_name) or {}
        proxies = group.get("proxies") or []
        selection = self.manager.get_selection(group_name)
        if selection and selection in proxies:
            current = selection
        else:
            current = proxies[0] if proxies else "DIRECT"
        # Resolve a reference to another group one or two levels deep.
        seen = set()
        while current in groups and current not in seen:
            seen.add(current)
            nested = groups[current]
            child_sel = self.manager.get_selection(current)
            children = nested.get("proxies") or []
            if child_sel and child_sel in children:
                current = child_sel
            else:
                current = children[0] if children else "DIRECT"
        return current

    def _chain_for_template(self, group: str) -> list[str]:
        mode = self.manager.store.state["settings"].get("mode", "rule")
        main_group = self.manager.main_group_name()
        if mode == "direct":
            return ["DIRECT"]
        if mode == "global":
            node = self._node_for_group(main_group)
            return ["GLOBAL", node]
        if not group or group in ("DIRECT", "REJECT"):
            return [group or "DIRECT"]
        node = self._node_for_group(group)
        if node in ("DIRECT", "REJECT"):
            return [node]
        return [node, group]

    def _add_connection(self) -> None:
        host, port, network, rule, group, process = random.choice(DEMO_TEMPLATES)
        mode = self.manager.store.state["settings"].get("mode", "rule")
        if mode == "direct":
            group, rule = "DIRECT", "Match"
        elif mode == "global":
            group, rule = "GLOBAL", "Match"
        chain = self._chain_for_template(group)
        if chain and chain[-1] == "REJECT":
            return
        source_port = random.randint(49152, 65000)
        conn_id = uuid.uuid4().hex[:12]
        now = time.time() - random.uniform(3, 150)
        upload = random.randint(12_000, 380_000)
        download = random.randint(300_000, 9_500_000)
        meta = {
            "id": conn_id,
            "host": host,
            "port": port,
            "network": network,
            "type": network,
            "rule": rule,
            "rulePayload": "",
            "chains": chain,
            "upload": upload,
            "download": download,
            "start": datetime.fromtimestamp(now).astimezone().isoformat(timespec="seconds"),
            "startEpoch": now,
            "process": process,
            "sourceIP": "127.0.0.1",
            "sourcePort": source_port,
            "destinationIP": f"198.18.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "sniffHost": host,
        }
        self.connections[conn_id] = meta

    def tick(self) -> tuple[float, float]:
        with self.lock:
            if not self.running:
                return 0.0, 0.0
            self.phase += 0.17
            wave = (math.sin(self.phase) + 1) / 2
            wave2 = (math.sin(self.phase * 0.43 + 1.4) + 1) / 2
            jitter = random.uniform(0.82, 1.18)
            down = (2.3 + 8.4 * wave + 3.2 * wave2) * 1024 * 1024 * jitter
            up = (0.22 + 1.15 * wave2 + 0.36 * wave) * 1024 * 1024 * random.uniform(0.8, 1.2)

            # Occasionally add or expire connections so the table feels alive.
            if len(self.connections) < 16 and random.random() < 0.22:
                self._add_connection()
            if len(self.connections) > 5 and random.random() < 0.08:
                oldest = min(self.connections.values(), key=lambda c: c["startEpoch"])
                self.connections.pop(oldest["id"], None)

            shares = []
            total_weight = 0.0
            for conn in self.connections.values():
                weight = random.uniform(0.4, 1.6)
                shares.append((conn, weight))
                total_weight += weight
            for conn, weight in shares:
                portion = weight / max(total_weight, 0.001)
                conn["download"] += int(down * portion)
                conn["upload"] += int(up * portion)

            now = time.time()
            if now - self._last_log_emit > random.uniform(2.8, 6.5):
                self._last_log_emit = now
                self._emit_log()
            return up, down

    def _emit_log(self) -> None:
        if not self.connections:
            return
        conn = random.choice(list(self.connections.values()))
        template = random.choice(DEMO_LOG_MESSAGES)
        chain_label = " → ".join(conn["chains"]) if conn["chains"] else "DIRECT"
        message = template.format(
            src=f"127.0.0.1:{conn['sourcePort']}",
            host=conn["host"],
            port=conn["port"],
            rule=conn["rule"],
            chain=chain_label,
            node=conn["chains"][0] if conn["chains"] else "DIRECT",
            delay=random.randint(38, 180),
            a=random.randint(1, 254),
            b=random.randint(1, 254),
        )
        roll = random.random()
        if roll < 0.035:
            self.manager.log("error", "connection reset by peer · " + conn["host"])
        elif roll < 0.14:
            self.manager.log("warning", "DNS cache miss for " + conn["host"] + " · fallback to nameserver")
        elif roll < 0.23:
            self.manager.log("debug", message)
        else:
            self.manager.log("info", message)

    def close_connection(self, conn_id: str) -> bool:
        with self.lock:
            return self.connections.pop(conn_id, None) is not None

    def close_all(self) -> None:
        with self.lock:
            self.connections.clear()

    def connection_list(self) -> list[dict]:
        with self.lock:
            items = list(self.connections.values())
        items.sort(key=lambda c: c.get("startEpoch", 0), reverse=True)
        return items

    def connection_count(self) -> int:
        with self.lock:
            return len(self.connections)


# ---------------------------------------------------------------------------
# Windows process helpers (stale core cleanup)
# ---------------------------------------------------------------------------


def windows_process_image_path(pid: int) -> str:
    if os.name != "nt":
        return ""
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
        if not handle:
            return ""
        try:
            size = ctypes.c_ulong(2048)
            buffer = ctypes.create_unicode_buffer(size.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
                return buffer.value
            return ""
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return ""


def console_window_state() -> dict:
    if os.name != "nt":
        return {"available": False, "visible": False, "supported": False}
    try:
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        kernel32.GetConsoleWindow.restype = ctypes.c_void_p
        user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
        user32.IsWindowVisible.restype = ctypes.c_int
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return {"available": False, "visible": False, "supported": True}
        return {"available": True, "visible": bool(user32.IsWindowVisible(hwnd)), "supported": True}
    except Exception:
        return {"available": False, "visible": False, "supported": False}


def set_console_window_visible(visible: bool) -> dict:
    if os.name != "nt":
        raise ValueError("当前系统不支持控制控制台窗口")
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    kernel32.GetConsoleWindow.restype = ctypes.c_void_p
    user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
    user32.ShowWindow.restype = ctypes.c_int
    user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
    user32.SetForegroundWindow.restype = ctypes.c_int
    hwnd = kernel32.GetConsoleWindow()
    if not hwnd:
        raise ValueError("当前进程没有控制台窗口（可能是后台/无窗口启动）")
    user32.ShowWindow(hwnd, 5 if visible else 0)  # SW_SHOW / SW_HIDE
    if visible:
        user32.SetForegroundWindow(hwnd)
    return console_window_state()


def windows_listener_pids(port: int) -> set[int]:
    if os.name != "nt":
        return set()
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=6,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    pids: set[int] = set()
    suffix = f":{int(port)}"
    for line in (proc.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[3].upper() == "LISTENING" and parts[1].endswith(suffix):
            try:
                pids.add(int(parts[4]))
            except ValueError:
                continue
    return pids


# ---------------------------------------------------------------------------
# Real Mihomo / Clash core
# ---------------------------------------------------------------------------


class CoreRuntime:
    def __init__(self, manager: "Manager") -> None:
        self.manager = manager
        self.lock = threading.RLock()
        self.process: subprocess.Popen | None = None
        self.path: str = ""
        self.started_at: float | None = None
        self.last_error: str = ""
        self.last_connections: list[dict] = []
        self.last_connection_count = 0
        self._last_totals: tuple[int, int] | None = None
        self._log_handle = None
        self._log_path = RUNTIME_DIR / "core.log"
        self._log_offset = 0
        self._api_failures = 0
        self._ready = False
        # Never route localhost controller calls through a system proxy.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @property
    def running(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    def _port_open(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=0.35):
                return True
        except OSError:
            return False

    def api(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        timeout: float = 2.5,
    ) -> Any:
        settings = self.manager.store.state["settings"]
        port = int(settings.get("controllerPort") or 9090)
        secret = str(settings.get("secret") or "")
        url = f"http://127.0.0.1:{port}{path}"
        payload = None
        headers = {"Accept": "application/json"}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=timeout) as response:
                raw = response.read()
                if not raw:
                    return {}
                return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            raise RuntimeError(f"内核 API 返回 {exc.code}: {detail or exc.reason}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"无法连接内核 API：{exc}") from exc

    def _build_config(self) -> Path:
        profile = self.manager.store.get_profile()
        if not profile:
            raise RuntimeError("当前没有可用配置")
        data, _ = self.manager.get_profile_data()
        settings = self.manager.store.state["settings"]
        data = copy.deepcopy(data)
        for key in ("port", "socks-port", "redir-port", "tproxy-port", "mixed-port", "external-controller", "secret"):
            data.pop(key, None)
        data["mixed-port"] = int(settings.get("mixedPort") or 7890)
        data["allow-lan"] = bool(settings.get("allowLan"))
        data["ipv6"] = bool(settings.get("ipv6"))
        data["mode"] = settings.get("mode", "rule")
        data["log-level"] = "info"
        data["external-controller"] = f"127.0.0.1:{int(settings.get('controllerPort') or 9090)}"
        data["secret"] = str(settings.get("secret") or "")
        # TUN is deliberately managed outside this panel; avoid an admin prompt.
        tun = data.get("tun")
        if isinstance(tun, dict):
            tun["enable"] = False

        # Some configs contain no groups. Mihomo still accepts them, but the UI
        # expects a selector so every node can be reached.
        proxies = data.get("proxies") or []
        groups = data.get("proxy-groups")
        if not groups and proxies:
            names = [p.get("name") for p in proxies if isinstance(p, dict) and p.get("name")]
            data["proxy-groups"] = [{"name": "🚀 节点选择", "type": "select", "proxies": names + ["DIRECT"]}]
            groups = data["proxy-groups"]
        if not data.get("rules"):
            data["rules"] = ["MATCH,DIRECT"]
        blocked_rules = self.manager.get_blocked_rules()
        route_rules = self.manager.get_route_rules()
        override_rules = blocked_rules + route_rules
        if override_rules:
            existing_rules = [str(rule) for rule in (data.get("rules") or [])]
            data["rules"] = override_rules + [
                rule for rule in existing_rules if rule not in override_rules
            ]

        # Normalize noisy health checks. A large provider config can otherwise
        # launch hundreds of HTTP checks while the controller is still booting,
        # flooding the UI with false errors and competing with /version.
        for group in data.get("proxy-groups") or []:
            if not isinstance(group, dict):
                continue
            if group.get("url"):
                group["url"] = prefer_https_test_url(group["url"])
            gtype = normalize_group_type(group.get("type") or "")
            if gtype in ("url-test", "fallback", "load-balance") and "lazy" not in group:
                group["lazy"] = True
        for provider in (data.get("proxy-providers") or {}).values():
            if not isinstance(provider, dict):
                continue
            health = provider.get("health-check")
            if isinstance(health, dict) and health.get("url"):
                health["url"] = prefer_https_test_url(health["url"])

        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        config_path = RUNTIME_DIR / "config.yaml"
        header = f"# Generated by {APP_NAME} at {now_iso()}\n"
        config_path.write_text(
            header + yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=1000),
            encoding="utf-8",
        )
        return config_path

    def _cleanup_stale_core(self, core_path: str, controller_port: int, mixed_port: int) -> None:
        if os.name != "nt":
            for port in (controller_port, mixed_port):
                if self._port_open("127.0.0.1", port):
                    raise RuntimeError(f"端口 {port} 已被占用，请先关闭占用程序")
            return
        listeners: dict[int, set[int]] = {}
        for port in (controller_port, mixed_port):
            pids = windows_listener_pids(port)
            if pids:
                listeners[port] = pids
        stale: set[int] = set()
        for port, pids in listeners.items():
            for pid in pids:
                image = windows_process_image_path(pid)
                image_name = Path(image).name.lower() if image else ""
                same_binary = bool(image) and Path(image).resolve() == Path(core_path).resolve()
                known_core = image_name in ("mihomo.exe", "clash-meta.exe", "clash.exe")
                if same_binary or known_core:
                    stale.add(pid)
                else:
                    raise RuntimeError(
                        f"端口 {port} 被进程 PID {pid} 占用"
                        + (f"（{image_name}）" if image_name else "")
                        + "，无法自动清理，请更换端口或关闭该程序"
                    )
        if not stale:
            return
        for pid in stale:
            self.manager.log("warning", f"检测到上次未退出的 Mihomo 进程 PID {pid}，正在自动结束")
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError):
                pass
        deadline = time.time() + 6
        while time.time() < deadline:
            busy = any(self._port_open("127.0.0.1", port) for port in (controller_port, mixed_port))
            if not busy:
                self.manager.log("info", "残留内核已清理，继续启动新内核")
                return
            time.sleep(0.25)
        raise RuntimeError("残留 Mihomo 进程无法结束，请手动终止 mihomo.exe 后重试")

    def start(self) -> None:
        with self.lock:
            if self.running:
                return
            settings = self.manager.store.state["settings"]
            path = self.manager.resolve_core_path()
            if not path:
                raise RuntimeError("未找到 Mihomo / Clash 内核，请先在设置中指定内核路径")
            controller_port = int(settings.get("controllerPort") or 9090)
            mixed_port = int(settings.get("mixedPort") or 7890)
            self._cleanup_stale_core(path, controller_port, mixed_port)
            config_path = self._build_config()
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            self._log_path.write_text("", encoding="utf-8")
            self._log_handle = self._log_path.open("ab", buffering=0)
            self._log_handle.write(
                (f"===== {APP_NAME} starting core at {now_iso()} =====\n").encode("utf-8")
            )
            command = [path, "-d", str(RUNTIME_DIR), "-f", str(config_path)]
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                self.process = subprocess.Popen(
                    command,
                    cwd=str(RUNTIME_DIR),
                    stdout=self._log_handle,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
            except OSError as exc:
                self._close_log()
                raise RuntimeError(f"无法启动内核：{exc}") from exc
            self.path = path
            self.started_at = time.time()
            self._log_offset = 0
            self._api_failures = 0
            self.last_error = ""
            self._ready = False
            ready = False
            # Large provider subscriptions can launch hundreds of health
            # checks immediately after boot. Give the controller API enough
            # room to answer without the sampler hammering /connections.
            deadline = time.time() + 32.0
            while time.time() < deadline:
                if self.process.poll() is not None:
                    break
                try:
                    self.api("GET", "/version", timeout=2.5)
                    ready = True
                    break
                except RuntimeError:
                    time.sleep(0.4)
            if not ready:
                if self.process.poll() is not None:
                    detail = f"内核进程已退出（退出码 {self.process.returncode}），请查看 data/runtime/core.log。"
                else:
                    detail = (
                        "内核进程已启动，但控制器 API 在 32 秒内没有响应。"
                        "可能是节点和策略组过多导致健康检查阻塞，或控制器端口被占用。"
                    )
                tail = self._read_log_tail()
                self.last_error = detail
                self.stop()
                raise RuntimeError(detail + ((" " + tail[-300:]) if tail else ""))
            self._ready = True
            self.manager.log("info", f"Mihomo 内核已启动 · {Path(path).name}")
            self.manager.log("info", f"混合端口 127.0.0.1:{settings.get('mixedPort')} · 控制器端口 {controller_port}")
            self.manager.apply_saved_selections()
            self.manager.log("info", "配置已加载，节点选择已同步")

    def stop(self) -> None:
        with self.lock:
            proc = self.process
            self.process = None
            self.started_at = None
            self._ready = False
            self.last_connections = []
            self.last_connection_count = 0
            self._last_totals = None
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=4)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            self._close_log()
        if proc:
            self.manager.log("info", "Mihomo 内核已停止")

    def _close_log(self) -> None:
        if self._log_handle:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None

    def _read_log_tail(self, limit: int = 4000) -> str:
        try:
            if not self._log_path.exists():
                return ""
            data = self._log_path.read_bytes()
            return data[-limit:].decode("utf-8", errors="replace").strip()
        except OSError:
            return ""

    def collect_logs(self) -> None:
        try:
            if not self._log_path.exists():
                return
            size = self._log_path.stat().st_size
            if size < self._log_offset:
                self._log_offset = 0
            if size == self._log_offset:
                return
            with self._log_path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._log_offset)
                chunk = fh.read(64_000)
                self._log_offset = fh.tell()
            for line in chunk.splitlines():
                line = line.strip()
                if not line or line.startswith("====="):
                    continue
                level = "info"
                lower = line.lower()
                if "level=error" in lower or "error" in lower and "no error" not in lower:
                    level = "error"
                elif "level=warning" in lower or "warn" in lower:
                    level = "warning"
                elif "level=debug" in lower:
                    level = "debug"
                clean = re.sub(r"^time=\"[^\"]+\"\s*", "", line)
                clean = re.sub(r"level=\w+\s*", "", clean)
                clean = re.sub(r"msg=\"(.*)\"$", r"\1", clean)
                self.manager.log(level, clean)
        except OSError:
            return

    def _parse_connections(self, payload: dict) -> tuple[list[dict], int, int]:
        items: list[dict] = []
        for item in payload.get("connections") or []:
            meta = item.get("metadata") or {}
            start = item.get("start") or now_iso()
            try:
                start_epoch = datetime.fromisoformat(start.replace("Z", "+00:00")).timestamp()
            except ValueError:
                start_epoch = time.time()
            destination = meta.get("destinationIP") or meta.get("host") or "-"
            items.append(
                {
                    "id": item.get("id"),
                    "host": meta.get("host") or destination,
                    "port": meta.get("destinationPort") or "",
                    "network": meta.get("network") or "tcp",
                    "type": meta.get("type") or "TCP",
                    "rule": item.get("rule") or "Match",
                    "rulePayload": item.get("rulePayload") or "",
                    "chains": item.get("chains") or [],
                    "upload": int(item.get("upload") or 0),
                    "download": int(item.get("download") or 0),
                    "start": start,
                    "startEpoch": start_epoch,
                    "process": meta.get("process") or "",
                    "processPath": meta.get("processPath") or "",
                    "sourceIP": meta.get("sourceIP") or "",
                    "sourcePort": meta.get("sourcePort") or "",
                    "destinationIP": destination,
                    "sniffHost": meta.get("host") or "",
                }
            )
        items.sort(key=lambda c: c["startEpoch"], reverse=True)
        return items, int(payload.get("uploadTotal") or 0), int(payload.get("downloadTotal") or 0)

    def poll(self) -> tuple[float, float, int]:
        # `running` becomes true as soon as the child is spawned; wait until
        # the controller health check completes before polling. Otherwise the
        # first /connections request can starve /version on a large config.
        if not self.running or not self._ready:
            return 0.0, 0.0, self.last_connection_count
        try:
            payload = self.api("GET", "/connections", timeout=4.0)
            self._api_failures = 0
            items, upload_total, download_total = self._parse_connections(payload)
            self.last_connections = items
            self.last_connection_count = len(items)
            if self._last_totals is None:
                up_rate = down_rate = 0.0
            else:
                old_up, old_down = self._last_totals
                up_rate = float(max(0, upload_total - old_up))
                down_rate = float(max(0, download_total - old_down))
            self._last_totals = (upload_total, download_total)
            self.collect_logs()
            return up_rate, down_rate, len(items)
        except RuntimeError as exc:
            self._api_failures += 1
            if self._api_failures == 4:
                self.manager.log("warning", f"内核 API 暂时不可用：{exc}")
            return 0.0, 0.0, self.last_connection_count

    def close_connection(self, conn_id: str) -> bool:
        if not self.running:
            return False
        try:
            self.api("DELETE", f"/connections/{urllib.parse.quote(conn_id, safe='')}")
            self.last_connections = [c for c in self.last_connections if c.get("id") != conn_id]
            self.last_connection_count = len(self.last_connections)
            return True
        except RuntimeError:
            return False

    def close_all(self) -> bool:
        if not self.running:
            return False
        try:
            self.api("DELETE", "/connections")
            self.last_connections = []
            self.last_connection_count = 0
            return True
        except RuntimeError:
            return False


# ---------------------------------------------------------------------------
# Windows application icons
# ---------------------------------------------------------------------------


def extract_executable_icon(executable: Path) -> bytes | None:
    """Extract the associated icon of a Windows executable as PNG bytes."""
    if os.name != "nt" or not executable.is_file() or executable.suffix.lower() != ".exe":
        return None
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return None
    script = r"""
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon($env:ICON_PATH)
if ($null -eq $icon) { exit 2 }
$bmp = $icon.ToBitmap()
$ms = New-Object System.IO.MemoryStream
$bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($ms.ToArray())
"""
    env = os.environ.copy()
    env["ICON_PATH"] = str(executable)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.run(
            [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=20,
            env=env,
            creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines:
        return None
    try:
        raw = base64.b64decode(lines[-1], validate=True)
    except (ValueError, binascii.Error):
        return None
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    return raw


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class Manager:
    def __init__(self) -> None:
        self.store = Store()
        self.demo = DemoRuntime(self)
        self.core = CoreRuntime(self)
        self.lock = threading.RLock()
        self.logs: deque[dict] = deque(maxlen=1000)
        self._log_id = 0
        self.history: deque[dict] = deque(maxlen=180)
        self.metrics_lock = threading.Lock()
        self.current_up = 0.0
        self.current_down = 0.0
        self.connection_count = 0
        self.session_up = 0.0
        self.session_down = 0.0
        self.kind: str | None = None
        self._sampler_stop = threading.Event()
        self._sampler_thread: threading.Thread | None = None
        self._profile_cache: dict[str, tuple[float, dict, dict]] = {}
        self._icon_cache: dict[str, bytes] = {}
        self._icon_lock = threading.Lock()
        self.connection_history: dict[str, dict] = {}
        self.connection_history_lock = threading.RLock()
        self._history_last_save = 0.0
        self._history_dirty = False
        self._load_connection_history()
        self.latency: dict[str, dict] = {}
        self.stats = self._load_stats()
        self._last_stats_save = 0.0
        self._last_core_detect: tuple[float, dict] | None = None
        self.boot_error = ""
        self.started_at = time.time()
        self._stats_lock = threading.Lock()
        self._runtime_seen = False
        self._last_kind = "demo"

    # -- logs --------------------------------------------------------------
    def log(self, level: str, message: str) -> None:
        with self.lock:
            self._log_id += 1
            entry = {
                "id": self._log_id,
                "time": now_iso(),
                "epoch": time.time(),
                "level": level if level in ("info", "warning", "error", "debug") else "info",
                "message": str(message),
            }
            self.logs.append(entry)
        try:
            print(f"[{entry['time']}] [{entry['level'].upper()}] {entry['message']}")
        except (UnicodeEncodeError, OSError):
            try:
                print(
                    f"[{entry['time']}] [{entry['level'].upper()}] "
                    f"{entry['message'].encode('ascii', 'replace').decode('ascii')}"
                )
            except OSError:
                pass

    def get_logs(self, after: int = 0, level: str = "", limit: int = 300) -> dict:
        with self.lock:
            entries = list(self.logs)
        if level and level != "all":
            entries = [entry for entry in entries if entry["level"] == level]
        if after:
            entries = [entry for entry in entries if entry["id"] > after]
            entries = entries[-limit:]
        else:
            entries = entries[-limit:]
        return {"logs": entries, "lastId": entries[-1]["id"] if entries else after}

    def clear_logs(self) -> None:
        with self.lock:
            self.logs.clear()

    # -- stats -------------------------------------------------------------
    def _load_stats(self) -> dict:
        raw = read_json(STATS_FILE, {})
        if not isinstance(raw, dict) or raw.get("date") != today_str():
            raw = {
                "date": today_str(),
                "demo": {"up": 9.86 * 1024**3, "down": 15.42 * 1024**3},
                "core": {"up": 0.0, "down": 0.0},
            }
            write_json(STATS_FILE, raw)
        raw.setdefault("demo", {"up": 0.0, "down": 0.0})
        raw.setdefault("core", {"up": 0.0, "down": 0.0})
        return raw

    def _save_stats(self) -> None:
        with self._stats_lock:
            write_json(STATS_FILE, self.stats)
            self._last_stats_save = time.time()

    def _record_traffic(self, kind: str | None, up: float, down: float) -> None:
        if kind not in ("demo", "core"):
            return
        today = today_str()
        if self.stats.get("date") != today:
            self.stats = {
                "date": today,
                "demo": {"up": 0.0, "down": 0.0},
                "core": {"up": 0.0, "down": 0.0},
            }
        bucket = self.stats.setdefault(kind, {"up": 0.0, "down": 0.0})
        bucket["up"] = float(bucket.get("up", 0)) + max(0.0, up)
        bucket["down"] = float(bucket.get("down", 0)) + max(0.0, down)
        self.session_up += max(0.0, up)
        self.session_down += max(0.0, down)
        if time.time() - self._last_stats_save > 12:
            self._save_stats()

    # -- connection history ------------------------------------------------
    @staticmethod
    def _connection_duration(record: dict, now: float | None = None) -> float:
        start = float(record.get("startEpoch") or 0)
        if not start:
            return 0.0
        if record.get("status") == "closed":
            end = float(record.get("closedAt") or record.get("lastSeen") or start)
        else:
            end = float(now if now is not None else time.time())
        return max(0.0, end - start)

    def _ingest_connections(self, items: list[dict], kind: str) -> None:
        """Merge a live snapshot into the session connection registry.

        Connections that disappear from the core keep their final counters and
        are marked closed instead of being removed from the UI.
        """
        now = time.time()
        active_ids = set()
        with self.connection_history_lock:
            for source in items or []:
                item = copy.deepcopy(source)
                conn_id = str(item.get("id") or "").strip()
                if not conn_id:
                    conn_id = f"{kind}:{item.get('host')}:{item.get('port')}:{item.get('startEpoch')}"
                item["id"] = conn_id
                active_ids.add(conn_id)
                record = self.connection_history.get(conn_id, {})
                record.update(item)
                record["status"] = "active"
                record["kind"] = kind
                record["lastSeen"] = now
                record.pop("closedAt", None)
                record["duration"] = self._connection_duration(record, now)
                self.connection_history[conn_id] = record
            for conn_id, record in self.connection_history.items():
                if (
                    record.get("status") == "active"
                    and record.get("kind") == kind
                    and conn_id not in active_ids
                ):
                    record["status"] = "closed"
                    record["closedAt"] = now
                    record["lastSeen"] = now
                    record["duration"] = self._connection_duration(record, now)
            # Keep memory bounded for very long sessions. Closed rows are
            # discarded only after 2000 retained records.
            closed = [
                (record.get("closedAt") or 0, conn_id)
                for conn_id, record in self.connection_history.items()
                if record.get("status") == "closed"
            ]
            if len(closed) > 2000:
                closed.sort()
                for _, conn_id in closed[: len(closed) - 2000]:
                    self.connection_history.pop(conn_id, None)
        self._save_connection_history()

    def _mark_all_connections_closed(self, kind: str | None = None) -> None:
        now = time.time()
        with self.connection_history_lock:
            for record in self.connection_history.values():
                if record.get("status") != "active":
                    continue
                if kind and record.get("kind") != kind:
                    continue
                record["status"] = "closed"
                record["closedAt"] = now
                record["lastSeen"] = now
                record["duration"] = self._connection_duration(record, now)
        self._save_connection_history(force=True)

    def _load_connection_history(self) -> None:
        raw = read_json(HISTORY_FILE, {})
        records = raw.get("connections", []) if isinstance(raw, dict) else raw
        if not isinstance(records, list):
            return
        now = time.time()
        with self.connection_history_lock:
            for source in records:
                if not isinstance(source, dict) or not source.get("id"):
                    continue
                record = copy.deepcopy(source)
                if record.get("status") != "closed":
                    record["status"] = "closed"
                    record["closedAt"] = record.get("lastSeen") or now
                record["duration"] = self._connection_duration(record, now)
                self.connection_history[str(record["id"])] = record
            closed = [
                (record.get("closedAt") or 0, conn_id)
                for conn_id, record in self.connection_history.items()
                if record.get("status") == "closed"
            ]
            if len(closed) > 2000:
                closed.sort()
                for _, conn_id in closed[: len(closed) - 2000]:
                    self.connection_history.pop(conn_id, None)

    def _save_connection_history(self, force: bool = False) -> None:
        with self.connection_history_lock:
            if not force and time.time() - self._history_last_save < 8:
                self._history_dirty = True
                return
            records = [copy.deepcopy(record) for record in self.connection_history.values()]
            self._history_last_save = time.time()
            self._history_dirty = False
        try:
            write_json(
                HISTORY_FILE,
                {
                    "version": 1,
                    "savedAt": now_iso(),
                    "connections": records,
                },
            )
        except OSError:
            pass

    def clear_closed_connections(self) -> int:
        with self.connection_history_lock:
            closed_ids = [
                conn_id for conn_id, record in self.connection_history.items()
                if record.get("status") == "closed"
            ]
            for conn_id in closed_ids:
                self.connection_history.pop(conn_id, None)
        self._save_connection_history(force=True)
        return len(closed_ids)

    def delete_connection_records(self, conn_ids: list[str]) -> int:
        removed = 0
        with self.connection_history_lock:
            for conn_id in conn_ids:
                record = self.connection_history.get(conn_id)
                if record and record.get("status") == "closed":
                    self.connection_history.pop(conn_id, None)
                    removed += 1
        if removed:
            self._save_connection_history(force=True)
        return removed

    # -- manual blocklist --------------------------------------------------
    def get_blocked_rules(self) -> list[str]:
        with self.store.lock:
            entries = copy.deepcopy(self.store.state.get("blocked", []))
        rules = []
        for entry in entries:
            rule = str(entry.get("rule") or "").strip()
            if rule and rule not in rules:
                rules.append(rule)
        return rules

    def _normalize_block(self, host: str, suffix: bool = False) -> dict:
        value = str(host or "").strip().lower().rstrip(".")
        if not value or any(ch in value for ch in " ,/@"):
            raise ValueError("无效的域名或 IP")
        is_ip = False
        try:
            address = ipaddress.ip_address(value)
            is_ip = True
            if isinstance(address, ipaddress.IPv6Address):
                rule = f"IP-CIDR6,{address}/128,REJECT,no-resolve"
            else:
                rule = f"IP-CIDR,{address}/32,REJECT,no-resolve"
            kind = "ip"
        except ValueError:
            if "." not in value or value.startswith(".") or value.endswith("."):
                raise ValueError("仅支持域名或 IP 地址")
            kind = "suffix" if suffix else "domain"
            rule = f"DOMAIN-SUFFIX,{value},REJECT" if suffix else f"DOMAIN,{value},REJECT"
        return {"value": value, "type": kind, "rule": rule, "is_ip": is_ip, "suffix": bool(suffix and not is_ip)}

    def add_blocks(self, hosts: list[str], suffix: bool = False, processes: list[str] | None = None) -> dict:
        normalized = []
        seen_values = set()
        for host in hosts or []:
            item = self._normalize_block(host, suffix=suffix)
            if item["value"] not in seen_values:
                seen_values.add(item["value"])
                normalized.append(item)
        process_names = []
        for process in processes or []:
            name = str(process or "").strip()
            if name and name.lower() not in {value.lower() for value in process_names}:
                process_names.append(name)
        if not normalized and not process_names:
            raise ValueError("没有可禁止的域名、IP 或进程")
        new_entries = []
        duplicates = []
        with self.store.lock:
            blocked = self.store.state.setdefault("blocked", [])
            existing = {str(entry.get("value", "")).lower(): entry for entry in blocked}
            for item in normalized:
                if item["value"] in existing:
                    duplicates.append(copy.deepcopy(existing[item["value"]]))
                    continue
                entry = {
                    "id": uuid.uuid4().hex[:10],
                    "value": item["value"],
                    "type": item["type"],
                    "rule": item["rule"],
                    "createdAt": now_iso(),
                }
                blocked.append(entry)
                new_entries.append(entry)
            for name in process_names:
                if name.lower() in existing:
                    duplicates.append(copy.deepcopy(existing[name.lower()]))
                    continue
                entry = {
                    "id": uuid.uuid4().hex[:10],
                    "value": name,
                    "type": "process",
                    "rule": f"PROCESS-NAME,{name},REJECT",
                    "createdAt": now_iso(),
                }
                blocked.append(entry)
                new_entries.append(entry)
            if new_entries:
                self.store.save()
        if new_entries:
            self.log("info", f"已添加 {len(new_entries)} 条禁止规则")
        reloaded = False
        if new_entries and self.core.running:
            reloaded = self.reload_core_config()
        closed = 0
        for item in normalized:
            closed += self._close_connections_matching(item["value"], item["is_ip"], item["suffix"])
        if process_names:
            closed += self._close_connections_for_rules([
                {"type": "PROCESS-NAME", "value": name} for name in process_names
            ])
        return {
            "entries": new_entries,
            "entry": new_entries[0] if new_entries else (duplicates[0] if duplicates else None),
            "duplicates": duplicates,
            "closed": closed,
            "reloaded": reloaded,
            "duplicate": not new_entries,
        }

    def add_block(self, host: str) -> dict:
        return self.add_blocks([host])

    def remove_block(self, entry_id: str) -> dict:
        with self.store.lock:
            blocked = self.store.state.setdefault("blocked", [])
            entry = next((item for item in blocked if item.get("id") == entry_id), None)
            if not entry:
                raise ValueError("禁止规则不存在")
            self.store.state["blocked"] = [item for item in blocked if item.get("id") != entry_id]
            self.store.save()
        reloaded = False
        if self.core.running:
            reloaded = self.reload_core_config()
        self.log("info", f"已移除禁止规则：{entry.get('rule', '')}")
        return {"entry": copy.deepcopy(entry), "reloaded": reloaded}

    # -- per-connection route overrides ------------------------------------
    def get_route_overrides(self) -> list[dict]:
        with self.store.lock:
            return copy.deepcopy(self.store.state.get("routeOverrides", []))

    def get_route_rules(self) -> list[str]:
        rules = []
        for entry in self.get_route_overrides():
            rule = str(entry.get("rule") or "").strip()
            if rule and rule not in rules:
                rules.append(rule)
        return rules

    @staticmethod
    def _route_rule(rule_type: str, value: str, target: str) -> str:
        if rule_type in ("DOMAIN", "DOMAIN-SUFFIX", "PROCESS-NAME"):
            return f"{rule_type},{value},{target}"
        if rule_type in ("IP-CIDR", "IP-CIDR6"):
            network = value if "/" in value else (value + "/128" if ":" in value else value + "/32")
            return f"{rule_type},{network},{target},no-resolve"
        raise ValueError("不支持的路由规则类型")

    def set_route_overrides(self, rules: list[dict], target: str) -> dict:
        with self.store.lock:
            data, _ = self.get_profile_data()
            groups = {
                str(group.get("name"))
                for group in data.get("proxy-groups") or []
                if isinstance(group, dict) and group.get("name")
            }
            clean_target = str(target or "").strip()
            if clean_target not in ("", "auto", "DIRECT") and clean_target not in groups:
                raise ValueError("目标策略组不存在")
        normalized: list[dict] = []
        for item in rules or []:
            if not isinstance(item, dict):
                continue
            rule_type = str(item.get("type") or "").upper()
            raw_value = str(item.get("value") or "").strip()
            value = raw_value if rule_type == "PROCESS-NAME" else raw_value.lower().rstrip(".")
            if rule_type not in ("DOMAIN", "DOMAIN-SUFFIX", "PROCESS-NAME", "IP-CIDR", "IP-CIDR6"):
                raise ValueError("不支持的路由规则类型")
            if not value:
                continue
            normalized.append({"type": rule_type, "value": value})
        if not normalized:
            raise ValueError("没有可用的匹配对象")
        clean_target = "" if clean_target in ("", "auto") else clean_target
        now = now_iso()
        with self.store.lock:
            entries = self.store.state.setdefault("routeOverrides", [])
            before = len(entries)
            keys = {(item["type"], item["value"].lower()) for item in normalized}
            entries = [
                entry for entry in entries
                if (str(entry.get("type")), str(entry.get("value")).lower()) not in keys
            ]
            if clean_target:
                for item in normalized:
                    entry = {
                        "id": uuid.uuid4().hex[:10],
                        "type": item["type"],
                        "value": item["value"],
                        "target": clean_target,
                        "rule": self._route_rule(item["type"], item["value"], clean_target),
                        "createdAt": now,
                    }
                    entries.append(entry)
            self.store.state["routeOverrides"] = entries
            self.store.save()
            changed = bool(clean_target) or len(entries) < before
        if changed:
            self.log(
                "info",
                ("已清除路由覆盖并跟随规则" if not clean_target else f"已设置 {len(normalized)} 条路由覆盖 → {clean_target}"),
            )
        reloaded = self.reload_core_config() if (changed and self.core.running) else False
        closed = self._close_connections_for_rules(normalized) if changed else 0
        return {"target": clean_target, "rules": normalized, "closed": closed, "reloaded": reloaded, "changed": changed}

    def _close_connections_for_rules(self, rules: list[dict]) -> int:
        if not rules:
            return 0
        def matches(record: dict) -> bool:
            host = str(record.get("host") or "").lower().rstrip(".")
            destination = str(record.get("destinationIP") or "").lower()
            process = str(record.get("process") or "").lower()
            for item in rules:
                rtype, value = item["type"], item["value"]
                if rtype == "DOMAIN" and host == value:
                    return True
                if rtype == "DOMAIN-SUFFIX" and (host == value or host.endswith("." + value)):
                    return True
                if rtype == "PROCESS-NAME" and process == value.lower():
                    return True
                if rtype in ("IP-CIDR", "IP-CIDR6"):
                    if destination == value or host == value:
                        return True
            return False
        closed = 0
        if self.core.running:
            for record in list(self.core.last_connections):
                if matches(record) and self.core.close_connection(str(record.get("id") or "")):
                    self._mark_connection_closed(str(record.get("id") or ""), save=False)
                    closed += 1
        elif self.demo.running:
            for record in self.demo.connection_list():
                if matches(record) and self.demo.close_connection(str(record.get("id") or "")):
                    self._mark_connection_closed(str(record.get("id") or ""), save=False)
                    closed += 1
        if closed:
            self._save_connection_history(force=True)
        return closed

    def _close_connections_matching(self, value: str, is_ip: bool, suffix: bool = False) -> int:
        def matches(record: dict) -> bool:
            host = str(record.get("host") or "").lower().rstrip(".")
            destination = str(record.get("destinationIP") or "").lower()
            if is_ip:
                return host == value or destination == value
            if suffix:
                return host == value or host.endswith("." + value)
            return host == value
        closed = 0
        if self.core.running:
            for record in list(self.core.last_connections):
                if matches(record) and self.core.close_connection(str(record.get("id") or "")):
                    self._mark_connection_closed(str(record.get("id") or ""), save=False)
                    closed += 1
        elif self.demo.running:
            for record in self.demo.connection_list():
                if matches(record) and self.demo.close_connection(str(record.get("id") or "")):
                    self._mark_connection_closed(str(record.get("id") or ""), save=False)
                    closed += 1
        if closed:
            self._save_connection_history(force=True)
        return closed

    # -- profile cache -----------------------------------------------------
    def get_profile_data(self, profile_id: str | None = None) -> tuple[dict, dict]:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("当前没有选中的配置")
        pid = profile["id"]
        path = self.store.profile_path(pid)
        mtime = path.stat().st_mtime if path.exists() else 0
        cached = self._profile_cache.get(pid)
        if cached and cached[0] == mtime:
            return copy.deepcopy(cached[1]), copy.deepcopy(cached[2])
        content = self.store.read_profile(pid)
        data, counts = self.store.parse(content)
        self._profile_cache[pid] = (mtime, data, counts)
        return copy.deepcopy(data), copy.deepcopy(counts)

    def invalidate_profile(self, profile_id: str | None = None) -> None:
        if profile_id:
            self._profile_cache.pop(profile_id, None)
        else:
            self._profile_cache.clear()

    def get_selection(self, group: str, profile_id: str | None = None) -> str | None:
        pid = profile_id or self.store.state.get("activeProfileId")
        return (self.store.state.get("selections", {}).get(pid) or {}).get(group)

    def set_selection(self, group: str, name: str, profile_id: str | None = None) -> None:
        pid = profile_id or self.store.state.get("activeProfileId")
        if not pid:
            raise ValueError("没有活动配置")
        selections = self.store.state.setdefault("selections", {}).setdefault(pid, {})
        selections[group] = name
        self.store.save()

    def main_group_name(self) -> str:
        try:
            data, _ = self.get_profile_data()
        except Exception:
            return "节点选择"
        groups = [g for g in data.get("proxy-groups") or [] if isinstance(g, dict)]
        for group in groups:
            if "节点选择" in str(group.get("name", "")) or "Proxy" == group.get("name"):
                return group.get("name") or "节点选择"
        for group in groups:
            if normalize_group_type(group.get("type")) == "select":
                return group.get("name") or "节点选择"
        return groups[0].get("name") if groups else "节点选择"

    # -- runtime state -----------------------------------------------------
    def is_running(self) -> bool:
        return self.core.running or self.demo.running

    def runtime_kind(self) -> str:
        if self.core.running:
            return "core"
        if self.demo.running:
            return "demo"
        return "stopped"

    def seed_history_if_needed(self) -> None:
        """Give the dashboard chart a full, pleasant first frame.

        The sampler may write one zero point before the demo runtime boots, so
        check the point count rather than simply testing for an empty deque.
        """
        with self.metrics_lock:
            if len(self.history) >= 10:
                return
            if not self.demo.running:
                return
            now = time.time()
            existing = list(self.history)
            self.history.clear()
            for i in range(100, 0, -1):
                phase = i / 7.0
                down = (
                    2.5
                    + 7.8 * (math.sin(phase) + 1) / 2
                    + 2.2 * (math.sin(phase * 0.4) + 1) / 2
                ) * 1024 * 1024
                up = (0.25 + 1.2 * (math.sin(phase * 0.8 + 1) + 1) / 2) * 1024 * 1024
                self.history.append(
                    {"t": now - i, "up": round(up, 2), "down": round(down, 2)}
                )
            latest = self.history[-1]["t"] if self.history else 0
            while existing and not existing[-1].get("up") and not existing[-1].get("down"):
                existing.pop()
            for point in existing:
                if point.get("t", 0) > latest:
                    self.history.append(point)

    def start_sampler(self) -> None:
        if self._sampler_thread and self._sampler_thread.is_alive():
            return
        self._sampler_stop.clear()
        self._sampler_thread = threading.Thread(target=self._sample_loop, name="pilot-sampler", daemon=True)
        self._sampler_thread.start()

    def _sample_loop(self) -> None:
        while not self._sampler_stop.is_set():
            started = time.time()
            up = down = 0.0
            count = 0
            kind: str | None = None
            try:
                if self.demo.running:
                    kind = "demo"
                    up, down = self.demo.tick()
                    count = self.demo.connection_count()
                    self._ingest_connections(self.demo.connection_list(), "demo")
                elif self.core.running:
                    kind = "core"
                    up, down, count = self.core.poll()
                    self._ingest_connections(self.core.last_connections, "core")
                else:
                    kind = None
            except Exception as exc:  # pragma: no cover - defensive
                self.log("error", f"采样线程异常：{exc}")
            if kind is not None:
                self._runtime_seen = True
                self._last_kind = kind
            self.current_up = up
            self.current_down = down
            self.connection_count = count
            self._record_traffic(kind, up, down)
            # Do not record the zero-rate beat that can happen before the
            # boot thread has selected and started an engine; it would put a
            # one-second hole in the otherwise seeded chart.
            if kind is not None or self._runtime_seen:
                with self.metrics_lock:
                    self.history.append(
                        {"t": time.time(), "up": round(up, 2), "down": round(down, 2)}
                    )
            self._watch_core_process()
            elapsed = time.time() - started
            self._sampler_stop.wait(max(0.25, 1.0 - elapsed))

    def _watch_core_process(self) -> None:
        if self.core.process is not None and self.core.process.poll() is not None:
            code = self.core.process.returncode
            self._mark_all_connections_closed("core")
            self.core.stop()
            self.kind = None
            self.log("error", f"Mihomo 内核意外退出（退出码 {code}），请检查日志")
            try:
                if self.get_system_proxy_status().get("ours") and self.get_system_proxy_status().get("enabled"):
                    self.apply_system_proxy(False, reason="内核意外退出，系统代理已自动关闭")
            except Exception:
                pass

    # -- engine lifecycle --------------------------------------------------
    def boot(self) -> None:
        settings = self.store.state["settings"]
        self.log("info", f"{APP_NAME} v{APP_VERSION} 正在初始化 · Python {platform.python_version()}")
        if settings.get("autoStart", True):
            try:
                self.start_engine(autostart=True)
            except Exception as exc:
                self.boot_error = str(exc)
                self.log("error", f"自动启动失败：{exc}")
        self.log("info", "控制台就绪 · 仅监听 127.0.0.1，数据不会离开本机")

    def start_engine(self, autostart: bool = False) -> dict:
        settings = self.store.state["settings"]
        mode = settings.get("engineMode", "demo")
        if self.is_running():
            return self.get_engine_status()
        detected = self.detect_core()
        if mode == "demo":
            if self.core.running:
                self.core.stop()
            self.kind = "demo"
            self.demo.start()
            self.log("info", "运行模式：演示内核（不产生真实代理流量）")
            return self.get_engine_status()
        if mode == "core" and not detected.get("path"):
            raise ValueError("未检测到 Mihomo 内核，请先在设置中填写内核路径")
        if mode == "auto" and not detected.get("path"):
            self.log("warning", "未检测到 Mihomo 内核，自动回退到演示内核")
            self.kind = "demo"
            self.demo.start()
            return self.get_engine_status()
        try:
            self.demo.stop()
            self.kind = "core"
            self.core.start()
            self.kind = "core"
            self.store.state["settings"]["systemProxy"] = self.get_system_proxy_status().get("ours", False)
            self.store.save()
            return self.get_engine_status()
        except Exception as exc:
            self.kind = None
            self.boot_error = str(exc)
            self.core.last_error = str(exc)
            self.core.stop()
            self.log("error", f"Mihomo 内核启动失败：{exc}")
            if mode == "auto":
                self.log("warning", f"真实内核启动失败，自动回退到演示模式：{exc}")
                self.boot_error = str(exc)
                self.demo.start()
                self.kind = "demo"
                return self.get_engine_status()
            raise

    def stop_engine(self) -> dict:
        was_core = self.core.running
        self._mark_all_connections_closed()
        if self.demo.running:
            self.demo.stop()
        if self.core.running:
            self.core.stop()
        self.kind = None
        self.current_up = 0.0
        self.current_down = 0.0
        self.connection_count = 0
        if was_core:
            status = self.get_system_proxy_status()
            if status.get("ours") and status.get("enabled"):
                self.apply_system_proxy(False, reason="内核已停止，系统代理已自动关闭")
        return self.get_engine_status()

    def restart_engine(self) -> dict:
        settings = self.store.state["settings"]
        was_system_proxy = self.get_system_proxy_status()
        self._mark_all_connections_closed()
        if self.demo.running:
            self.demo.stop()
        if self.core.running:
            self.core.stop()
        self.kind = None
        self.start_engine()
        if was_system_proxy.get("ours") and settings.get("engineMode") == "core" and self.core.running:
            try:
                self.apply_system_proxy(True)
            except Exception as exc:
                self.log("warning", f"恢复系统代理失败：{exc}")
        return self.get_engine_status()

    def get_engine_status(self) -> dict:
        settings = self.store.state["settings"]
        detected = self.detect_core()
        kind = self.runtime_kind()
        return {
            "running": kind != "stopped",
            "kind": kind,
            "demo": kind == "demo",
            "core": kind == "core",
            "mode": settings.get("engineMode", "demo"),
            "systemMode": settings.get("mode", "rule"),
            "startedAt": self.demo.started_at if kind == "demo" else (self.core.started_at if kind == "core" else None),
            "corePath": self.core.path if kind == "core" else detected.get("path", ""),
            "detectedPath": detected.get("path", ""),
            "version": detected.get("version", ""),
            "lastError": self.boot_error or self.core.last_error,
            "mixedPort": settings.get("mixedPort"),
            "controllerPort": settings.get("controllerPort"),
        }

    def detect_core(self, force: bool = False) -> dict:
        cached = self._last_core_detect
        if cached and not force and time.time() - cached[0] < 20:
            return copy.deepcopy(cached[1])
        settings = self.store.state["settings"]
        candidates: list[Path] = []
        configured = str(settings.get("corePath") or "").strip()
        if configured:
            candidates.append(Path(configured).expanduser())
        # The panel's own bin directory wins over PATH lookup. On Windows,
        # `shutil.which` can also return an unrelated or wrong-architecture
        # file from the current directory, so explicit local paths come first.
        candidates.extend(
            [
                BASE_DIR / "bin" / "mihomo.exe",
                BASE_DIR / "bin" / "clash-meta.exe",
                BASE_DIR / "core" / "mihomo.exe",
                BASE_DIR / "mihomo.exe",
            ]
        )
        env_path = os.environ.get("MIHOMO_PATH") or os.environ.get("CLASH_PATH")
        if env_path:
            candidates.append(Path(env_path))
        for command in ("mihomo", "clash-meta", "clash"):
            found = shutil.which(command)
            if found:
                candidates.append(Path(found))
        candidates.extend(
            [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "mihomo" / "mihomo.exe",
                Path(os.environ.get("USERPROFILE", "")) / "scoop" / "apps" / "mihomo" / "current" / "mihomo.exe",
                Path("C:/Program Files/Mihomo/mihomo.exe"),
                Path("C:/Program Files/Clash Meta/mihomo.exe"),
            ]
        )
        result = {"path": "", "version": ""}
        seen: set[str] = set()
        for candidate in candidates:
            try:
                if not candidate or not candidate.is_file():
                    continue
                resolved = str(candidate.resolve())
                if resolved in seen:
                    continue
                seen.add(resolved)
                result = {"path": resolved, "version": self._probe_core_version(resolved)}
                break
            except OSError:
                continue
        self._last_core_detect = (time.time(), copy.deepcopy(result))
        return result

    def _probe_core_version(self, path: str) -> str:
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            proc = subprocess.run(
                [path, "-v"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=flags,
            )
            output = (proc.stdout or proc.stderr or "").strip()
            return output.splitlines()[0][:120] if output else "Mihomo Core"
        except (OSError, subprocess.SubprocessError):
            return "未知版本"

    def resolve_core_path(self) -> str:
        configured = str(self.store.state["settings"].get("corePath") or "").strip()
        if configured and Path(configured).is_file():
            return str(Path(configured).resolve())
        return self.detect_core().get("path", "")

    # -- proxies -----------------------------------------------------------
    def _latency_for(self, profile_id: str, name: str, seed: bool = True) -> dict:
        key = f"{profile_id}::{name}"
        entry = self.latency.get(key)
        if entry:
            return entry
        if not seed:
            return {"latency": None, "testedAt": None, "timeout": False}
        rng = random.Random(hashlib.sha256(key.encode("utf-8")).hexdigest())
        base = rng.randint(32, 205)
        entry = {"latency": base, "testedAt": now_iso(), "timeout": False}
        self.latency[key] = entry
        return entry

    def _node_object(
        self,
        profile_id: str,
        name: str,
        kind: str,
        raw_type: str,
        meta: dict | None,
        latency_source: dict | None = None,
        allow_seed: bool = True,
    ) -> dict:
        flag, country, code = guess_country(name)
        meta = meta or {}
        if latency_source is not None:
            entry = latency_source
        else:
            entry = self._latency_for(profile_id, name, seed=(kind == "node" and allow_seed))
        server = str(meta.get("server") or "")
        port = meta.get("port") or ""
        return {
            "name": name,
            "displayName": strip_flag(name),
            "kind": kind,
            "type": raw_type or ("group" if kind == "group" else "proxy"),
            "protocol": protocol_label(raw_type),
            "server": server,
            "port": port,
            "country": country,
            "flag": flag,
            "code": code,
            "latency": entry.get("latency"),
            "testedAt": entry.get("testedAt"),
            "timeout": entry.get("timeout", False),
        }

    def _meta_map(self, data: dict) -> dict:
        result = {}
        for proxy in data.get("proxies") or []:
            if isinstance(proxy, dict) and proxy.get("name"):
                result[proxy["name"]] = proxy
        return result

    def _demo_groups(self, data: dict, profile_id: str, allow_seed: bool = True) -> list[dict]:
        meta = self._meta_map(data)
        groups_config = [g for g in data.get("proxy-groups") or [] if isinstance(g, dict)]
        group_names = {g.get("name") for g in groups_config}
        proxy_names = {p.get("name") for p in data.get("proxies") or [] if isinstance(p, dict)}
        builtin = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
        groups: list[dict] = []
        current_map: dict[str, str] = {}
        for group in groups_config:
            gname = group.get("name") or "策略组"
            gtype = normalize_group_type(group.get("type"))
            children = [str(x) for x in (group.get("proxies") or [])]
            nodes = []
            for child in children:
                if child in group_names:
                    node = self._node_object(profile_id, child, "group", "group", None)
                elif child in builtin:
                    node = self._node_object(profile_id, child, "builtin", child.lower(), None)
                else:
                    node = self._node_object(
                        profile_id,
                        child,
                        "node",
                        (meta.get(child) or {}).get("type", ""),
                        meta.get(child),
                        allow_seed=allow_seed,
                    )
                nodes.append(node)
            direct_nodes = [n for n in nodes if n["kind"] == "node"]
            selection = self.get_selection(gname, profile_id)
            if selection in children:
                now = selection
            elif gtype in ("url-test", "fallback", "load-balance") and direct_nodes:
                now = min(
                    direct_nodes,
                    key=lambda n: (n.get("latency") if isinstance(n.get("latency"), int) else 9999),
                )["name"]
            else:
                now = children[0] if children else "DIRECT"
            current_map[gname] = now
            groups.append(
                {
                    "name": gname,
                    "type": gtype,
                    "now": now,
                    "nodes": nodes,
                    "nodeCount": len(direct_nodes),
                    "isMain": False,
                    "rawType": group.get("type", "select"),
                }
            )
        main_name = self.main_group_name()
        for group in groups:
            group["isMain"] = group["name"] == main_name
        return groups

    def _real_groups(self, data: dict, profile_id: str) -> list[dict]:
        payload = self.core.api("GET", "/proxies", timeout=3.0)
        proxies = payload.get("proxies") or {}
        meta = self._meta_map(data)
        groups: list[dict] = []
        for name, item in proxies.items():
            raw_type = item.get("type") or ""
            if "all" not in item or raw_type.lower() in ("direct", "reject", "compatible"):
                continue
            nodes = []
            for child in item.get("all") or []:
                child_data = proxies.get(child) or {}
                if "all" in child_data:
                    nodes.append(self._node_object(profile_id, child, "group", "group", None))
                elif child in ("DIRECT", "REJECT"):
                    nodes.append(self._node_object(profile_id, child, "builtin", child.lower(), None))
                else:
                    history = child_data.get("history") or []
                    latency_entry = None
                    if history:
                        try:
                            delay = int(history[-1].get("delay") or 0)
                            if delay > 0:
                                latency_entry = {
                                    "latency": delay,
                                    "testedAt": history[-1].get("time") or now_iso(),
                                    "timeout": False,
                                }
                                self.latency[f"{profile_id}::{child}"] = latency_entry
                        except (TypeError, ValueError):
                            pass
                    nodes.append(
                        self._node_object(
                            profile_id,
                            child,
                            "node",
                            child_data.get("type") or (meta.get(child) or {}).get("type", ""),
                            meta.get(child),
                            latency_source=latency_entry
                            or {"latency": None, "testedAt": None, "timeout": False},
                        )
                    )
            main_name = self.main_group_name()
            groups.append(
                {
                    "name": name,
                    "type": normalize_group_type(raw_type),
                    "now": item.get("now") or "",
                    "nodes": nodes,
                    "nodeCount": len([n for n in nodes if n["kind"] == "node"]),
                    "isMain": name == main_name,
                    "rawType": raw_type,
                }
            )
        if not groups:
            groups = self._demo_groups(data, profile_id, allow_seed=False)
        return groups

    def get_proxies(self) -> dict:
        profile = self.store.get_profile()
        if not profile:
            raise ValueError("当前没有可用配置")
        data, _ = self.get_profile_data()
        if self.core.running:
            try:
                groups = self._real_groups(data, profile["id"])
            except RuntimeError:
                groups = self._demo_groups(data, profile["id"], allow_seed=False)
        else:
            groups = self._demo_groups(data, profile["id"], allow_seed=self.demo.running)
        return {
            "profile": {"id": profile["id"], "name": profile["name"]},
            "mode": self.store.state["settings"].get("mode", "rule"),
            "groups": groups,
            "mainGroup": self.main_group_name(),
            "running": self.is_running(),
            "kind": self.runtime_kind(),
            "updatedAt": now_iso(),
        }

    def select_proxy(self, group: str, name: str) -> dict:
        group = str(group or "").strip()
        name = str(name or "").strip()
        if not group or not name:
            raise ValueError("缺少策略组或节点")
        try:
            data, _ = self.get_profile_data()
        except Exception as exc:
            raise ValueError(str(exc)) from exc
        groups = {g.get("name"): g for g in data.get("proxy-groups") or [] if isinstance(g, dict)}
        group_cfg = groups.get(group)
        if not group_cfg and not self.core.running:
            raise ValueError("策略组不存在")
        children = [str(x) for x in ((group_cfg or {}).get("proxies") or [])]
        if self.core.running:
            # Provider-backed groups may expose nodes that are not written into
            # the YAML group itself, so trust the live core group membership.
            try:
                live = self.core.api("GET", f"/proxies/{urllib.parse.quote(group, safe='')}")
                live_children = live.get("all") if isinstance(live, dict) else None
                if live_children:
                    children = [str(x) for x in live_children]
            except RuntimeError:
                pass
        if name not in children:
            raise ValueError("该节点不在当前策略组中")
        if self.core.running:
            self.core.api("PUT", f"/proxies/{urllib.parse.quote(group, safe='')}", {"name": name})
        self.set_selection(group, name)
        self.log("info", f"已切换 {group} → {name}")
        return {"group": group, "now": name}

    def test_proxy(self, name: str) -> dict:
        profile = self.store.get_profile()
        if not profile:
            raise ValueError("当前没有可用配置")
        profile_id = profile["id"]
        if self.core.running:
            if name in ("DIRECT", "REJECT"):
                raise ValueError("内置策略不支持延迟测试")
            try:
                encoded = urllib.parse.quote(name, safe="")
                result = self.core.api(
                    "GET",
                    f"/proxies/{encoded}/delay?timeout=5000&url={urllib.parse.quote('https://www.gstatic.com/generate_204', safe='')}",
                    timeout=6.0,
                )
                latency = int(result.get("delay") or 0)
                entry = {
                    "latency": latency if latency > 0 else None,
                    "testedAt": now_iso(),
                    "timeout": latency <= 0,
                }
            except RuntimeError:
                entry = {"latency": None, "testedAt": now_iso(), "timeout": True}
        elif self.demo.running:
            time.sleep(random.uniform(0.12, 0.35))
            if random.random() < 0.06:
                entry = {"latency": None, "testedAt": now_iso(), "timeout": True}
            else:
                entry = {"latency": random.randint(32, 228), "testedAt": now_iso(), "timeout": False}
        else:
            raise ValueError("内核未运行，请先启动内核再测试延迟")
        self.latency[f"{profile_id}::{name}"] = entry
        self.log(
            "debug" if entry.get("latency") else "warning",
            f"延迟测试 {name}: {str(entry.get('latency')) + 'ms' if entry.get('latency') else '超时'}",
        )
        return {"name": name, **entry}

    def test_group(self, group: str) -> dict:
        proxies = self.get_proxies()
        selected = next((g for g in proxies["groups"] if g["name"] == group), None)
        if not selected:
            raise ValueError("策略组不存在")
        # Group children may themselves be policy groups. The native group
        # delay endpoint can test those as well as ordinary nodes.
        names = [n["name"] for n in selected["nodes"] if n["kind"] in ("node", "group")]
        profile = self.store.get_profile()
        profile_id = profile["id"] if profile else "unknown"
        tested_at = now_iso()
        results_by_name: dict[str, dict] = {}

        if self.core.running and names:
            try:
                payload = self.core.api(
                    "GET",
                    f"/group/{urllib.parse.quote(group, safe='')}/delay"
                    f"?url={urllib.parse.quote('https://www.gstatic.com/generate_204', safe='')}"
                    "&timeout=5000",
                    timeout=18.0,
                )
                if isinstance(payload, dict):
                    valid = 0
                    for name in names:
                        raw_delay = payload.get(name)
                        try:
                            delay = int(raw_delay) if raw_delay is not None else 0
                        except (TypeError, ValueError):
                            delay = 0
                        entry = {
                            "name": name,
                            "latency": delay if delay > 0 else None,
                            "testedAt": tested_at,
                            "timeout": delay <= 0,
                        }
                        if delay > 0:
                            valid += 1
                            self.latency[f"{profile_id}::{name}"] = {
                                "latency": delay,
                                "testedAt": tested_at,
                                "timeout": False,
                            }
                        results_by_name[name] = entry
                    if any(name in payload for name in names) or not names:
                        results = [results_by_name[name] for name in names if name in results_by_name]
                        self.log(
                            "info",
                            f"测速完成 {group} · {valid}/{len(names)} 个节点有响应",
                        )
                        return {
                            "group": group,
                            "results": results,
                            "testedAt": tested_at,
                            "native": True,
                        }
            except RuntimeError as exc:
                self.log("debug", f"策略组原生测速不可用，回退逐节点测速：{exc}")

        # Fallback for older cores or failed group endpoint.
        workers = 8 if self.core.running else 6
        if names:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(self.test_proxy, name): name for name in names}
                for future in as_completed(futures):
                    name = futures[future]
                    try:
                        results_by_name[name] = future.result()
                    except Exception as exc:
                        results_by_name[name] = {
                            "name": name,
                            "latency": None,
                            "timeout": True,
                            "testedAt": now_iso(),
                            "error": str(exc),
                        }
        results = [results_by_name[name] for name in names if name in results_by_name]
        self.log("info", f"测速完成 {group} · {len(results)} 个节点")
        return {"group": group, "results": results, "testedAt": now_iso(), "native": False}

    def apply_saved_selections(self) -> None:
        if not self.core.running:
            return
        try:
            data, _ = self.get_profile_data()
        except Exception:
            return
        for group in data.get("proxy-groups") or []:
            if not isinstance(group, dict):
                continue
            name = group.get("name")
            selection = self.get_selection(name)
            children = group.get("proxies") or []
            if selection and selection in children:
                try:
                    self.core.api("PUT", f"/proxies/{urllib.parse.quote(name, safe='')}", {"name": selection})
                except RuntimeError:
                    continue

    # -- rules -------------------------------------------------------------
    def get_rules(self) -> dict:
        profile = self.store.get_profile()
        data, _ = self.get_profile_data()
        raw_rules = data.get("rules") or []
        rules = [parse_rule(raw, index) for index, raw in enumerate(raw_rules)]
        groups = []
        for group in data.get("proxy-groups") or []:
            if isinstance(group, dict) and group.get("name"):
                groups.append(group["name"])
        return {
            "profile": {"id": profile["id"], "name": profile["name"]},
            "rules": rules,
            "groups": groups,
            "builtins": ["DIRECT", "REJECT"],
            "running": self.is_running(),
            "kind": self.runtime_kind(),
        }

    def _save_rules(self, data: dict) -> None:
        profile = self.store.get_profile()
        if not profile:
            raise ValueError("当前没有可用配置")
        content = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=1000)
        header = f"# Updated by {APP_NAME} at {now_iso()}\n"
        self.store.write_profile(profile["id"], header + content)
        _, counts = self.store.parse(header + content)
        self.store.update_profile_meta(profile["id"], counts=counts, updatedAt=now_iso())
        self.invalidate_profile(profile["id"])
        if self.core.running:
            self.reload_core_config()

    def _normalize_rule_input(self, payload: dict) -> dict:
        rtype = str(payload.get("type") or "DOMAIN-SUFFIX").upper().strip()
        target = str(payload.get("target") or "DIRECT").strip()
        rule_payload = str(payload.get("payload") or "").strip()
        if rtype not in RULE_TYPES:
            raise ValueError("不支持的规则类型")
        if rtype != "MATCH" and not rule_payload:
            raise ValueError("请填写规则内容")
        if not target:
            raise ValueError("请选择目标策略")
        options = []
        if payload.get("noResolve"):
            options.append("no-resolve")
        return {
            "type": rtype,
            "payload": rule_payload,
            "target": target,
            "options": options,
            "noResolve": bool(payload.get("noResolve")),
        }

    def add_rule(self, payload: dict) -> dict:
        data, _ = self.get_profile_data()
        rule = self._normalize_rule_input(payload)
        rules = list(data.get("rules") or [])
        raw = format_rule(rule)
        insert_at = len(rules)
        for index, existing in enumerate(rules):
            if str(existing).upper().startswith("MATCH,"):
                insert_at = index
                break
        rules.insert(insert_at, raw)
        data["rules"] = rules
        self._save_rules(data)
        self.log("info", f"已添加规则 {raw}")
        return {"index": insert_at, "rule": parse_rule(raw, insert_at)}

    def update_rule(self, index: int, payload: dict) -> dict:
        data, _ = self.get_profile_data()
        rules = list(data.get("rules") or [])
        if index < 0 or index >= len(rules):
            raise ValueError("规则不存在")
        rule = self._normalize_rule_input(payload)
        raw = format_rule(rule)
        rules[index] = raw
        data["rules"] = rules
        self._save_rules(data)
        self.log("info", f"已更新规则 {raw}")
        return {"index": index, "rule": parse_rule(raw, index)}

    def delete_rule(self, index: int) -> None:
        data, _ = self.get_profile_data()
        rules = list(data.get("rules") or [])
        if index < 0 or index >= len(rules):
            raise ValueError("规则不存在")
        removed = rules.pop(index)
        data["rules"] = rules
        self._save_rules(data)
        self.log("info", f"已删除规则 {removed}")

    def reload_core_config(self) -> bool:
        if not self.core.running:
            return False
        try:
            config_path = RUNTIME_DIR / "config.yaml"
            self.core._build_config()
            self.core.api(
                "PUT",
                "/configs?force=true",
                {"path": str(config_path)},
                timeout=4.0,
            )
            self.apply_saved_selections()
            self.log("info", "内核配置已热重载")
            return True
        except Exception as exc:
            self.log("warning", f"配置热重载失败，将在下次启动时生效：{exc}")
            return False

    # -- connections -------------------------------------------------------
    def get_connections(self) -> dict:
        kind = self.runtime_kind()
        if self.core.running:
            self._ingest_connections(self.core.last_connections, "core")
        elif self.demo.running:
            self._ingest_connections(self.demo.connection_list(), "demo")
        else:
            self._mark_all_connections_closed()
        now = time.time()
        with self.connection_history_lock:
            records = [copy.deepcopy(record) for record in self.connection_history.values()]
        for record in records:
            record.setdefault("status", "active")
            record["duration"] = self._connection_duration(record, now)
            record.setdefault("closedAt", None)
        records.sort(key=lambda record: (record.get("status") == "active", record.get("startEpoch") or 0), reverse=True)
        active = [record for record in records if record.get("status") == "active"]
        closed = [record for record in records if record.get("status") != "active"]
        total_upload = sum(int(record.get("upload") or 0) for record in records)
        total_download = sum(int(record.get("download") or 0) for record in records)
        total_duration = sum(float(record.get("duration") or 0) for record in records)
        active_duration = sum(float(record.get("duration") or 0) for record in active)
        return {
            "connections": records,
            "count": len(active),
            "totalCount": len(records),
            "activeCount": len(active),
            "closedCount": len(closed),
            "uploadTotal": total_upload,
            "downloadTotal": total_download,
            "totalDuration": round(total_duration, 3),
            "activeDuration": round(active_duration, 3),
            "running": self.is_running(),
            "kind": kind,
        }

    def _mark_connection_closed(self, conn_id: str, save: bool = True) -> None:
        changed = False
        now = time.time()
        with self.connection_history_lock:
            record = self.connection_history.get(conn_id)
            if record and record.get("status") == "active":
                record["status"] = "closed"
                record["closedAt"] = now
                record["lastSeen"] = now
                record["duration"] = self._connection_duration(record, now)
                changed = True
        if changed and save:
            self._save_connection_history(force=True)

    def close_connection(self, conn_id: str) -> bool:
        ok = False
        if self.core.running:
            ok = self.core.close_connection(conn_id)
        elif self.demo.running:
            ok = self.demo.close_connection(conn_id)
        if ok:
            self._mark_connection_closed(conn_id)
        return ok

    def close_all_connections(self) -> None:
        if self.core.running:
            self.core.close_all()
        if self.demo.running:
            self.demo.close_all()
        self._mark_all_connections_closed()
        self.log("info", "已关闭全部活动连接")

    # -- metrics -----------------------------------------------------------
    def get_metrics(self) -> dict:
        kind = self.runtime_kind()
        bucket_key = kind if kind in ("core", "demo") else (self._last_kind or "demo")
        bucket = self.stats.get(bucket_key, {"up": 0.0, "down": 0.0})
        with self.metrics_lock:
            history = list(self.history)
        peak = max((point["down"] for point in history[-60:]), default=0)
        return {
            "running": kind != "stopped",
            "kind": kind,
            "up": round(self.current_up, 2),
            "down": round(self.current_down, 2),
            "peakDown": round(peak, 2),
            "connectionCount": self.connection_count,
            "todayUp": round(float(bucket.get("up", 0)), 2),
            "todayDown": round(float(bucket.get("down", 0)), 2),
            "sessionUp": round(self.session_up, 2),
            "sessionDown": round(self.session_down, 2),
            "history": history,
            "updatedAt": now_iso(),
        }

    # -- system proxy ------------------------------------------------------
    def get_system_proxy_status(self) -> dict:
        current = read_windows_proxy()
        settings = self.store.state["settings"]
        port = int(settings.get("mixedPort") or 7890)
        expected = f"127.0.0.1:{port}"
        enabled = bool(current.get("enabled"))
        server = str(current.get("server") or "")
        ours = enabled and (expected in server or f"127.0.0.1:{port}" in server)
        return {
            "supported": current.get("supported", False),
            "enabled": enabled,
            "server": server,
            "expected": expected,
            "ours": ours,
            "managed": PROXY_BACKUP_FILE.exists(),
            "coreRunning": self.core.running,
            "detail": current.get("error") or "",
        }

    def apply_system_proxy(self, enabled: bool, reason: str = "") -> dict:
        settings = self.store.state["settings"]
        if enabled and not self.core.running:
            raise ValueError("启用系统代理需要先安装并启动真实的 Mihomo 内核；演示模式不会接管网络")
        port = int(settings.get("mixedPort") or 7890)
        status = set_windows_proxy(enabled, port, str(settings.get("bypass") or DEFAULT_BYPASS))
        settings["systemProxy"] = bool(status.get("enabled"))
        self.store.save()
        if reason:
            self.log("info", reason)
        self.log("info", "系统代理已开启 → 127.0.0.1:%s" % port if enabled else "系统代理已关闭")
        return status

    # -- settings ----------------------------------------------------------
    def update_settings(self, payload: dict) -> dict:
        settings = self.store.state["settings"]
        allowed = {
            "engineMode",
            "autoStart",
            "corePath",
            "mixedPort",
            "controllerPort",
            "secret",
            "allowLan",
            "ipv6",
            "mode",
            "bypass",
            "theme",
            "accent",
            "textScale",
        }
        updates = {k: v for k, v in (payload or {}).items() if k in allowed}
        if "engineMode" in updates and updates["engineMode"] not in ("demo", "auto", "core"):
            raise ValueError("无效的运行模式")
        if "mode" in updates and updates["mode"] not in ("rule", "global", "direct"):
            raise ValueError("无效的代理模式")
        if "textScale" in updates:
            try:
                updates["textScale"] = float(updates["textScale"])
            except (TypeError, ValueError):
                raise ValueError("无效的文字大小")
            if not 0.8 <= updates["textScale"] <= 1.5:
                raise ValueError("文字缩放范围应为 80% - 150%")
        for key in ("mixedPort", "controllerPort"):
            if key in updates:
                try:
                    port = int(updates[key])
                except (TypeError, ValueError):
                    raise ValueError("端口必须是数字")
                if not 1 <= port <= 65535:
                    raise ValueError("端口范围应为 1-65535")
                updates[key] = port
        if updates.get("mixedPort") and updates.get("controllerPort") and updates["mixedPort"] == updates["controllerPort"]:
            raise ValueError("混合端口与控制器端口不能相同")
        if "corePath" in updates:
            path = str(updates["corePath"] or "").strip()
            if path and not Path(path).expanduser().is_file():
                raise ValueError("指定的内核文件不存在")
            updates["corePath"] = str(Path(path).expanduser()) if path else ""
            self._last_core_detect = None
        old_mode = settings.get("mode")
        restart_keys = {"mixedPort", "controllerPort", "secret", "allowLan", "ipv6"}
        restart_required = self.core.running and any(
            key in updates and updates.get(key) != settings.get(key) for key in restart_keys
        )
        settings.update(updates)
        self.store.save()
        if "mode" in updates and old_mode != updates["mode"] and self.core.running:
            try:
                self.core.api("PATCH", "/configs", {"mode": updates["mode"]})
                self.log("info", f"代理模式已切换为 {updates['mode']}")
            except RuntimeError as exc:
                self.log("warning", f"代理模式同步失败：{exc}")
        status = self.get_system_proxy_status()
        if status.get("ours") and status.get("enabled") and "bypass" in updates and "mixedPort" not in updates:
            # Apply bypass changes immediately, but never point the system proxy
            # at a new mixed-port before the core has actually restarted.
            try:
                set_windows_proxy(
                    True,
                    int(settings.get("mixedPort") or 7890),
                    str(settings.get("bypass") or DEFAULT_BYPASS),
                )
            except Exception as exc:
                self.log("warning", f"系统代理绕过列表更新失败：{exc}")
        return {
            "settings": copy.deepcopy(settings),
            "restartRequired": restart_required,
            "engine": self.get_engine_status(),
        }

    # -- state snapshot ----------------------------------------------------
    def get_state(self) -> dict:
        with self.store.lock:
            profiles = copy.deepcopy(self.store.state["profiles"])
            active = self.store.get_profile()
            settings = copy.deepcopy(self.store.state["settings"])
            selections = copy.deepcopy(
                self.store.state.get("selections", {}).get(self.store.state.get("activeProfileId"), {})
            )
            blocked = copy.deepcopy(self.store.state.get("blocked", []))
            route_overrides = copy.deepcopy(self.store.state.get("routeOverrides", []))
        return {
            "app": {
                "name": APP_NAME,
                "version": APP_VERSION,
                "python": platform.python_version(),
                "platform": platform.system(),
            },
            "settings": settings,
            "profiles": profiles,
            "activeProfileId": self.store.state.get("activeProfileId"),
            "activeProfile": active,
            "selections": selections,
            "blocked": blocked,
            "routeOverrides": route_overrides,
            "mainGroup": self.main_group_name(),
            "engine": self.get_engine_status(),
            "systemProxy": self.get_system_proxy_status(),
            "stats": {
                "todayUp": self.get_metrics()["todayUp"],
                "todayDown": self.get_metrics()["todayDown"],
            },
            "bootError": self.boot_error,
        }

    def download_profile(self, profile_id: str) -> tuple[str, str]:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("配置不存在")
        return self.store.read_profile(profile_id), f"{profile['name']}.yaml"

    # -- application icons -------------------------------------------------
    def get_app_icon(self, path_text: str) -> dict:
        if os.name != "nt":
            raise ValueError("当前系统不支持提取 Windows 程序图标")
        path = Path(str(path_text or "").strip()).expanduser()
        if not path_text or not path.is_file() or path.suffix.lower() != ".exe":
            raise ValueError("程序路径无效")
        resolved = path.resolve()
        try:
            stat = resolved.stat()
        except OSError as exc:
            raise ValueError("无法读取程序文件") from exc
        key = hashlib.sha256(
            f"{resolved}|{stat.st_mtime_ns}|{stat.st_size}".encode("utf-8")
        ).hexdigest()[:32]
        with self._icon_lock:
            cached = self._icon_cache.get(key)
            if cached is not None:
                return {
                    "path": str(resolved),
                    "name": resolved.stem,
                    "icon": "data:image/png;base64," + base64.b64encode(cached).decode("ascii"),
                    "cached": True,
                }
            ICON_DIR.mkdir(parents=True, exist_ok=True)
            icon_path = ICON_DIR / f"{key}.png"
            if icon_path.is_file():
                try:
                    cached = icon_path.read_bytes()
                except OSError:
                    cached = None
            if not cached:
                cached = extract_executable_icon(resolved)
                if cached:
                    try:
                        icon_path.write_bytes(cached)
                    except OSError:
                        pass
            if not cached:
                raise ValueError("无法提取该程序的图标")
            self._icon_cache[key] = cached
            return {
                "path": str(resolved),
                "name": resolved.stem,
                "icon": "data:image/png;base64," + base64.b64encode(cached).decode("ascii"),
                "cached": False,
            }

    # -- subscription fetch ------------------------------------------------
    def fetch_subscription(self, url: str) -> tuple[str, dict | None]:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("订阅链接必须使用 http 或 https")
        headers = {
            "User-Agent": "clash.meta/1.19.0 ClashPilot/1.0",
            "Accept": "text/yaml, application/yaml, text/plain, */*",
            "Accept-Encoding": "identity",
        }
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                raw = response.read(MAX_BODY_BYTES + 1)
                if len(raw) > MAX_BODY_BYTES:
                    raise ValueError("订阅内容超过 12 MB 限制")
                charset = response.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                subscription = parse_subscription_userinfo(response.headers.get("subscription-userinfo"))
        except urllib.error.HTTPError as exc:
            raise ValueError(f"订阅下载失败：HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ValueError(f"订阅下载失败：{exc}") from exc
        text = possible_base64_yaml(text)
        return text, subscription

    def import_profile(self, payload: dict) -> dict:
        mode = str(payload.get("mode") or "content")
        name = str(payload.get("name") or "").strip()
        url = str(payload.get("url") or "").strip()
        subscription = None
        if mode == "url":
            if not url:
                raise ValueError("请输入订阅链接")
            content, subscription = self.fetch_subscription(url)
            meta = self.store.create_profile(content, name=name, url=url, remote=True, subscription=subscription)
            self.log("info", f"订阅已导入：{meta['name']} · {meta['counts']['proxies']} 个节点")
        else:
            content = str(payload.get("content") or "")
            if not content.strip():
                raise ValueError("配置文件内容为空")
            content = possible_base64_yaml(content)
            meta = self.store.create_profile(content, name=name or str(payload.get("filename") or ""), remote=False)
            self.log("info", f"配置已导入：{meta['name']} · {meta['counts']['proxies']} 个节点")
        return meta

    def refresh_profile(self, profile_id: str) -> dict:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("配置不存在")
        if not profile.get("remote") or not profile.get("url"):
            raise ValueError("本地配置无法刷新，请重新导入")
        content, subscription = self.fetch_subscription(profile["url"])
        data, counts = self.store.parse(content)
        self.store.write_profile(profile_id, content)
        self.invalidate_profile(profile_id)
        meta = self.store.update_profile_meta(
            profile_id,
            counts=counts,
            subscription=subscription,
            updatedAt=now_iso(),
        )
        self.log("info", f"订阅已刷新：{profile['name']}")
        if self.store.state.get("activeProfileId") == profile_id and self.core.running:
            self.reload_core_config()
        return meta or profile

    def delete_profile(self, profile_id: str) -> dict:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("配置不存在")
        was_active = self.store.state.get("activeProfileId") == profile_id
        was_running = self.core.running
        self.store.delete_profile(profile_id)
        self.invalidate_profile(profile_id)
        self.log("info", f"已删除配置：{profile['name']}")
        restarted = False
        if was_active and was_running:
            try:
                self._mark_all_connections_closed("core")
                self.core.stop()
                self.core.start()
                restarted = True
            except Exception as exc:
                self.log("error", f"删除活动配置后内核重启失败：{exc}")
                self.boot_error = str(exc)
                try:
                    status = self.get_system_proxy_status()
                    if status.get("ours") and status.get("enabled"):
                        self.apply_system_proxy(False, reason="内核启动失败，系统代理已自动关闭")
                except Exception:
                    pass
        return {"activeProfileId": self.store.state.get("activeProfileId"), "restarted": restarted}

    def activate_profile(self, profile_id: str) -> dict:
        profile = self.store.get_profile(profile_id)
        if not profile:
            raise ValueError("配置不存在")
        previous = self.store.state.get("activeProfileId")
        self.store.state["activeProfileId"] = profile_id
        self.store.state.setdefault("selections", {}).setdefault(profile_id, {})
        self.store.save()
        self.log("info", f"已激活配置：{profile['name']}")
        restart = False
        if previous != profile_id and self.core.running:
            try:
                self._mark_all_connections_closed("core")
                self.core.stop()
                self.core.start()
                restart = True
            except Exception as exc:
                self.log("error", f"切换配置后内核重启失败：{exc}")
                self.boot_error = str(exc)
                try:
                    status = self.get_system_proxy_status()
                    if status.get("ours") and status.get("enabled"):
                        self.apply_system_proxy(False, reason="内核启动失败，系统代理已自动关闭")
                except Exception:
                    pass
        return {"activeProfileId": profile_id, "restarted": restart, "error": self.boot_error if restart is False and previous != profile_id else ""}

    # -- shutdown ----------------------------------------------------------
    def shutdown(self) -> None:
        try:
            self._sampler_stop.set()
            status = self.get_system_proxy_status()
            if status.get("ours") and status.get("enabled"):
                try:
                    self.apply_system_proxy(False, reason="应用退出，系统代理已自动恢复")
                except Exception:
                    pass
            if self.core.running:
                self.core.stop()
            if self.demo.running:
                self.demo.stop()
            self._save_connection_history(force=True)
            self._save_stats()
            self.store.save()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Windows system proxy helpers
# ---------------------------------------------------------------------------


def read_windows_proxy() -> dict:
    if os.name != "nt":
        return {"supported": False, "enabled": False, "server": "", "error": "仅 Windows 支持系统代理"}
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_REG_PATH) as key:
            try:
                enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
            except FileNotFoundError:
                enable = 0
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""
            try:
                override, _ = winreg.QueryValueEx(key, "ProxyOverride")
            except FileNotFoundError:
                override = ""
        return {
            "supported": True,
            "enabled": bool(enable),
            "server": str(server or ""),
            "override": str(override or ""),
            "error": "",
        }
    except OSError as exc:
        return {"supported": True, "enabled": False, "server": "", "error": str(exc)}


def _notify_wininet() -> None:
    if os.name != "nt":
        return
    try:
        wininet = ctypes.windll.Wininet
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
        wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
    except Exception:
        pass


def set_windows_proxy(enabled: bool, port: int, bypass: str) -> dict:
    if os.name != "nt":
        raise ValueError("仅 Windows 支持自动配置系统代理")
    import winreg

    current = read_windows_proxy()
    server = f"127.0.0.1:{port}"
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            PROXY_REG_PATH,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        ) as key:
            if enabled:
                if not PROXY_BACKUP_FILE.exists():
                    backup = {
                        "enable": int(current.get("enabled", False)),
                        "server": current.get("server", ""),
                        "override": current.get("override", ""),
                        "createdAt": now_iso(),
                    }
                    write_json(PROXY_BACKUP_FILE, backup)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass)
            else:
                if PROXY_BACKUP_FILE.exists():
                    backup = read_json(PROXY_BACKUP_FILE, {})
                    current_server = str(current.get("server") or "")
                    # Only restore if the system proxy is still the one this
                    # app wrote. Never disable a proxy another app replaced.
                    if current_server in (server, "") or server in current_server:
                        winreg.SetValueEx(
                            key,
                            "ProxyEnable",
                            0,
                            winreg.REG_DWORD,
                            int(backup.get("enable", 0)),
                        )
                        winreg.SetValueEx(
                            key,
                            "ProxyServer",
                            0,
                            winreg.REG_SZ,
                            str(backup.get("server", "")),
                        )
                        winreg.SetValueEx(
                            key,
                            "ProxyOverride",
                            0,
                            winreg.REG_SZ,
                            str(backup.get("override", DEFAULT_BYPASS)),
                        )
                    try:
                        PROXY_BACKUP_FILE.unlink()
                    except OSError:
                        pass
                else:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    except OSError as exc:
        raise ValueError(f"无法修改系统代理设置：{exc}") from exc
    _notify_wininet()
    return read_windows_proxy()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


class PilotServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler], manager: Manager):
        super().__init__(server_address, handler)
        self.manager = manager


class Handler(BaseHTTPRequestHandler):
    server_version = f"ClashPilot/{APP_VERSION}"
    protocol_version = "HTTP/1.1"

    @property
    def manager(self) -> Manager:
        return self.server.manager  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if args and ("404" in str(args[0]) or "500" in str(args[0])):
            print(f"[http] {self.address_string()} {fmt % args}")

    def handle_one_request(self) -> None:
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True

    # -- low-level output --------------------------------------------------
    def _send(self, data: bytes, content_type: str, status: int = 200, extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra:
            for key, value in extra.items():
                self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, value: Any, status: int = 200) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self._send(data, "application/json; charset=utf-8", status)

    def send_error_json(self, message: str, status: int = 400) -> None:
        self.send_json({"error": message, "status": status}, status)

    def send_download(self, text: str, filename: str, content_type: str = "application/yaml; charset=utf-8") -> None:
        data = text.encode("utf-8")
        quoted = urllib.parse.quote(filename)
        self._send(
            data,
            content_type,
            200,
            {"Content-Disposition": f"attachment; filename*=UTF-8''{quoted}"},
        )

    def _read_body(self) -> dict:
        # Always consume the body, even for endpoints that ignore it. Otherwise
        # an HTTP/1.1 keep-alive connection would parse the leftover JSON as the
        # next request line (e.g. "{}GET /api/state").
        if getattr(self, "_body_ready", False):
            return copy.deepcopy(getattr(self, "_cached_body", {}))
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError("无效的请求长度")
        if length <= 0:
            self._cached_body = {}
            self._body_ready = True
            return {}
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            raise ApiError("请求体过大", 413)
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            self._cached_body = {}
            self._body_ready = True
            raise ApiError("请求体不是有效的 JSON") from exc
        if not isinstance(value, dict):
            self._cached_body = {}
            self._body_ready = True
            raise ApiError("请求体格式不正确")
        self._cached_body = value
        self._body_ready = True
        return copy.deepcopy(value)

    def _check_origin(self) -> None:
        host_header = (self.headers.get("Host") or "").strip()
        if host_header.startswith("["):
            hostname = host_header[1:].split("]", 1)[0].lower()
        else:
            hostname = host_header.split(":", 1)[0].lower()
        allowed_hosts = {"127.0.0.1", "localhost", "::1"}
        bind_host = str(self.server.server_address[0]).lower()
        if bind_host not in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            allowed_hosts.add(bind_host)
        if hostname not in allowed_hosts:
            raise ApiError("仅允许通过本机地址访问控制台", 403)
        origin = self.headers.get("Origin")
        if not origin:
            return
        port = self.server.server_port
        allowed_origins = {
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
            f"http://[::1]:{port}",
        }
        if origin not in allowed_origins:
            raise ApiError("拒绝跨站请求", 403)

    # -- HTTP verbs --------------------------------------------------------
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def do_PUT(self) -> None:
        self._route("PUT")

    def do_DELETE(self) -> None:
        self._route("DELETE")

    # -- routing -----------------------------------------------------------
    def _route(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Handler instances serve several keep-alive requests, so body state
        # must be cleared per request.
        self._body_ready = False
        self._cached_body = {}
        try:
            self._check_origin()
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                try:
                    content_length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    content_length = 0
                if content_length > 0:
                    self._read_body()
            if path.startswith("/api/"):
                self._api(method, path, urllib.parse.parse_qs(parsed.query))
                return
            if method == "GET" and path in ("/", "/index.html", "/main.html"):
                self._serve_main()
                return
            if method == "GET" and path == "/favicon.ico":
                self._serve_favicon()
                return
            if method == "GET" and path == "/favicon.svg":
                self._serve_favicon()
                return
            self.send_error_json("Not found", 404)
        except ApiError as exc:
            self.send_error_json(exc.message, exc.status)
        except ValueError as exc:
            self.send_error_json(str(exc), 400)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            traceback.print_exc()
            self.send_error_json(f"服务器内部错误：{exc}", 500)

    def _serve_main(self) -> None:
        path = BASE_DIR / "main.html"
        if not path.exists():
            self._send(
                "<h1>main.html not found</h1>".encode("utf-8"),
                "text/html; charset=utf-8",
                500,
            )
            return
        self._send(path.read_bytes(), "text/html; charset=utf-8")

    def _serve_favicon(self) -> None:
        svg = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#8b5cf6"/><stop offset="1" stop-color="#22d3ee"/></linearGradient></defs>
<rect width="64" height="64" rx="16" fill="#0b1020"/><path d="M18 43V21l14 13 14-13v22" fill="none" stroke="url(#g)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/><circle cx="32" cy="46" r="3" fill="#22d3ee"/></svg>"""
        self._send(svg, "image/svg+xml")

    def _api(self, method: str, path: str, query: dict) -> None:
        manager = self.manager

        # ---- read-only ---------------------------------------------------
        if method == "GET" and path == "/api/health":
            self.send_json({"ok": True, "app": APP_NAME, "version": APP_VERSION})
            return
        if method == "GET" and path == "/api/state":
            self.send_json(manager.get_state())
            return
        if method == "GET" and path == "/api/metrics":
            self.send_json(manager.get_metrics())
            return
        if method == "GET" and path == "/api/proxies":
            self.send_json(manager.get_proxies())
            return
        if method == "GET" and path == "/api/rules":
            self.send_json(manager.get_rules())
            return
        if method == "GET" and path == "/api/connections":
            self.send_json(manager.get_connections())
            return
        if method == "GET" and path == "/api/logs":
            after = int((query.get("after") or ["0"])[0] or 0)
            level = (query.get("level") or [""])[0]
            self.send_json(manager.get_logs(after=after, level=level))
            return
        if method == "GET" and path == "/api/profiles":
            state = manager.get_state()
            self.send_json({"profiles": state["profiles"], "activeProfileId": state["activeProfileId"]})
            return
        if method == "GET" and path == "/api/app-icon":
            executable = (query.get("path") or [""])[0]
            try:
                self.send_json(manager.get_app_icon(executable))
            except ValueError as exc:
                raise ApiError(str(exc), 404) from exc
            return
        if method == "GET" and path == "/api/backup":
            state = manager.get_state()
            profiles = {}
            for profile in state["profiles"]:
                try:
                    profiles[profile["id"]] = manager.store.read_profile(profile["id"])
                except ValueError:
                    profiles[profile["id"]] = ""
            payload = {
                "app": APP_NAME,
                "version": APP_VERSION,
                "createdAt": now_iso(),
                "state": manager.store.state,
                "profiles": profiles,
            }
            self.send_download(
                json.dumps(payload, ensure_ascii=False, indent=2),
                f"clash-pilot-backup-{today_str()}.json",
                "application/json; charset=utf-8",
            )
            return

        # ---- profiles ----------------------------------------------------
        match = re.fullmatch(r"/api/profiles/([A-Za-z0-9_-]+)/export", path)
        if method == "GET" and match:
            content, filename = manager.download_profile(match.group(1))
            self.send_download(content, filename)
            return

        if method == "POST" and path == "/api/profiles/import":
            body = self._read_body()
            self.send_json(manager.import_profile(body))
            return

        match = re.fullmatch(r"/api/profiles/([A-Za-z0-9_-]+)/refresh", path)
        if method == "POST" and match:
            self.send_json(manager.refresh_profile(match.group(1)))
            return

        match = re.fullmatch(r"/api/profiles/([A-Za-z0-9_-]+)/activate", path)
        if method == "POST" and match:
            self.send_json(manager.activate_profile(match.group(1)))
            return

        match = re.fullmatch(r"/api/profiles/([A-Za-z0-9_-]+)", path)
        if method == "DELETE" and match:
            profile_id = match.group(1)
            self.send_json({"ok": True, **manager.delete_profile(profile_id)})
            return

        # ---- proxy actions ----------------------------------------------
        if method == "POST" and path == "/api/proxies/select":
            body = self._read_body()
            self.send_json(manager.select_proxy(str(body.get("group") or ""), str(body.get("name") or "")))
            return
        if method == "POST" and path == "/api/proxies/test":
            body = self._read_body()
            self.send_json(manager.test_proxy(str(body.get("name") or "")))
            return
        if method == "POST" and path == "/api/proxies/test-group":
            body = self._read_body()
            self.send_json(manager.test_group(str(body.get("group") or "")))
            return

        # ---- rules -------------------------------------------------------
        if method == "POST" and path == "/api/rules":
            self.send_json(manager.add_rule(self._read_body()))
            return
        match = re.fullmatch(r"/api/rules/(\d+)", path)
        if method == "PUT" and match:
            self.send_json(manager.update_rule(int(match.group(1)), self._read_body()))
            return
        if method == "DELETE" and match:
            manager.delete_rule(int(match.group(1)))
            self.send_json({"ok": True})
            return
        if method == "POST" and path == "/api/rules/reload":
            self.send_json({"reloaded": manager.reload_core_config()})
            return

        # ---- connections -------------------------------------------------
        if method == "DELETE" and path == "/api/connections":
            manager.close_all_connections()
            self.send_json({"ok": True})
            return
        if method == "POST" and path == "/api/connections/clear-closed":
            cleared = manager.clear_closed_connections()
            self.send_json({"ok": True, "cleared": cleared})
            return
        if method == "POST" and path == "/api/connections/delete-history":
            body = self._read_body()
            ids = body.get("ids") if isinstance(body.get("ids"), list) else []
            removed = manager.delete_connection_records([str(value) for value in ids])
            self.send_json({"ok": True, "removed": removed})
            return
        match = re.fullmatch(r"/api/connections/([^/]+)", path)
        if method == "DELETE" and match:
            conn_id = urllib.parse.unquote(match.group(1))
            ok = manager.close_connection(conn_id)
            if not ok and manager.is_running():
                raise ApiError("连接不存在或已关闭", 404)
            self.send_json({"ok": True})
            return

        # ---- blocklist ---------------------------------------------------
        if method == "POST" and path == "/api/block":
            body = self._read_body()
            hosts = body.get("hosts") if isinstance(body.get("hosts"), list) else [body.get("host")]
            processes = body.get("processes") if isinstance(body.get("processes"), list) else []
            try:
                result = manager.add_blocks(
                    [str(value) for value in hosts if value],
                    suffix=bool(body.get("suffix")),
                    processes=[str(value) for value in processes if value],
                )
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            self.send_json(result)
            return
        match = re.fullmatch(r"/api/block/([A-Za-z0-9_-]+)", path)
        if method == "DELETE" and match:
            try:
                result = manager.remove_block(match.group(1))
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            self.send_json(result)
            return

        # ---- route overrides ---------------------------------------------
        if method == "POST" and path == "/api/route-overrides":
            body = self._read_body()
            try:
                result = manager.set_route_overrides(
                    body.get("rules") if isinstance(body.get("rules"), list) else [],
                    str(body.get("target") or ""),
                )
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            self.send_json(result)
            return

        # ---- logs --------------------------------------------------------
        if method == "POST" and path == "/api/logs/clear":
            manager.clear_logs()
            self.send_json({"ok": True})
            return

        # ---- engine ------------------------------------------------------
        if method == "POST" and path == "/api/engine/start":
            try:
                manager.start_engine()
            except Exception as exc:
                raise ApiError(str(exc), 500) from exc
            self.send_json({"ok": True, "engine": manager.get_engine_status()})
            return
        if method == "POST" and path == "/api/engine/stop":
            self.send_json({"ok": True, "engine": manager.stop_engine()})
            return
        if method == "POST" and path == "/api/engine/restart":
            try:
                manager.restart_engine()
            except Exception as exc:
                raise ApiError(str(exc), 500) from exc
            self.send_json({"ok": True, "engine": manager.get_engine_status()})
            return
        if method == "POST" and path == "/api/engine/detect":
            self.send_json(manager.detect_core(force=True))
            return
        if method == "POST" and path == "/api/engine/system-proxy":
            body = self._read_body()
            try:
                status = manager.apply_system_proxy(bool(body.get("enabled")))
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            self.send_json({"ok": True, "systemProxy": status, "engine": manager.get_engine_status()})
            return
        if method == "GET" and path == "/api/console/window":
            self.send_json(console_window_state())
            return
        if method == "POST" and path == "/api/console/window":
            body = self._read_body()
            try:
                state = set_console_window_visible(bool(body.get("visible")))
            except ValueError as exc:
                raise ApiError(str(exc)) from exc
            self.send_json(state)
            return

        # ---- settings ----------------------------------------------------
        if method == "PUT" and path == "/api/settings":
            body = self._read_body()
            self.send_json(manager.update_settings(body))
            return

        if method == "POST" and path == "/api/open-data":
            self._open_data_folder()
            self.send_json({"ok": True})
            return

        raise ApiError("Not found", 404)

    def _open_data_folder(self) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(DATA_DIR))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(DATA_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(DATA_DIR)])
        except Exception as exc:
            raise ApiError(f"无法打开数据目录：{exc}") from exc


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def find_free_port(preferred: int, host: str = "127.0.0.1") -> int:
    for port in range(preferred, preferred + 30):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, port))
                return port
        except OSError:
            continue
    raise RuntimeError("找不到可用端口")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - local Clash dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_UI_PORT, help="dashboard port")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (localhost by default)")
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    args = parser.parse_args()

    if yaml is None:
        print("缺少依赖 PyYAML。请运行：python -m pip install -r requirements.txt")
        return 1

    try:
        manager = Manager()
    except Exception as exc:
        print(f"初始化失败：{exc}")
        return 1
    manager.start_sampler()
    threading.Thread(target=manager.boot, name="pilot-boot", daemon=True).start()

    port = find_free_port(args.port, args.host)
    try:
        server = PilotServer((args.host, port), Handler, manager)
    except OSError as exc:
        print(f"无法启动控制台服务：{exc}")
        return 1

    url = f"http://127.0.0.1:{port}"
    print()
    print("  ╭──────────────────────────────────────────────╮")
    print("  │  CLASH PILOT · NETWORK CONTROL               │")
    print(f"  │  {url:<42}│")
    print("  ╰──────────────────────────────────────────────╯")
    print("  按 Ctrl+C 停止控制台")
    print()

    if not args.no_browser:
        threading.Timer(0.65, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever(poll_interval=0.4)
    except KeyboardInterrupt:
        print("\n正在关闭...")
    finally:
        manager.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
