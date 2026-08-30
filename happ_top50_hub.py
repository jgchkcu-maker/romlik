#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
КОДЕКС АРХИВА «ПОСЛЕДНИЙ КОДЕКС» // ГОД 3047
МОДУЛЬ: HAPP_TOP50_HUB.PY
НАЗНАЧЕНИЕ: Энергоэффективный генератор единой подписки ТОП-50 для HApp / Sing-box
            с гарантированным включением рабочих узлов Белых Списков (SNI/CIDR)
===============================================================================
"""

import asyncio
import base64
import glob
import http.server
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from typing import List, Dict, Optional, Set, Tuple

# // Гарантия поддержки Unicode/UTF-8 в консоли Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


class CodexNode:
    """
    // Квант информации об узле связи
    """
    def __init__(self, raw_uri: str, protocol: str, host: str, port: int, original_remark: str = "", is_whitelist: bool = False):
        self.raw_uri = raw_uri
        self.protocol = protocol
        self.host = host
        self.port = port
        self.original_remark = original_remark
        self.is_whitelist = is_whitelist
        self.latency_ms: Optional[float] = None
        self.is_alive: bool = False
        self.tls_verified: bool = False
        self.formatted_uri: str = raw_uri
        # // Параметры Reality/VLESS для реальной проверки через xray-core
        self.uuid: str = ""
        self.flow: str = ""
        self.reality_pbk: str = ""
        self.reality_sid: str = ""
        self.reality_fp: str = ""
        self.network_type: str = "tcp"
        self.country_code: str = ""
        self.country_name: str = ""
        self.country_flag: str = ""
        self.sni_host: str = ""

    def key(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"


class CodexParser:
    """
    // Декодер древних форматов туннелирования
    """
    @staticmethod
    def decode_b64(data: str) -> str:
        clean = data.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        padding = len(clean) % 4
        if padding != 0:
            clean += "=" * (4 - padding)
        try:
            return base64.b64decode(clean).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @classmethod
    def parse_uri(cls, uri: str, is_whitelist: bool = False) -> Optional[CodexNode]:
        uri = uri.strip()
        if not uri or "://" not in uri:
            return None

        protocol = uri.split("://")[0].lower()

        try:
            if protocol == "vmess":
                b64_part = uri[8:].split("#")[0].split("?")[0]
                decoded_json = cls.decode_b64(b64_part)
                if not decoded_json:
                    return None
                data = json.loads(decoded_json)
                host = str(data.get("add", "")).strip()
                port = int(data.get("port", 0))
                remark = str(data.get("ps", "")).strip()
                if host and port > 0:
                    return CodexNode(uri, "vmess", host, port, remark, is_whitelist)

            elif protocol in ("ss", "shadowsocks"):
                parsed = urllib.parse.urlparse(uri)
                remark = urllib.parse.unquote(parsed.fragment or "")
                netloc = parsed.netloc
                if "@" in netloc:
                    _, host_port = netloc.split("@", 1)
                    host, port_str = host_port.split(":")
                    return CodexNode(uri, "shadowsocks", host, int(port_str), remark, is_whitelist)
                else:
                    decoded = cls.decode_b64(netloc)
                    if "@" in decoded:
                        _, host_port = decoded.split("@", 1)
                        host, port_str = host_port.split(":")
                        return CodexNode(uri, "shadowsocks", host, int(port_str), remark, is_whitelist)

            elif protocol in ("vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "juicity"):
                parsed = urllib.parse.urlparse(uri)
                host = parsed.hostname
                port = parsed.port
                remark = urllib.parse.unquote(parsed.fragment or "")
                if host and port:
                    node = CodexNode(uri, protocol, host, port, remark, is_whitelist)
                    # Извлекаем параметры из запроса
                    # (некоторые источники кодируют & как &amp; — декодируем)
                    query_str = parsed.query.replace("&amp;", "&")
                    query = urllib.parse.parse_qs(query_str)
                    # SNI / serverName
                    sni_values = query.get("sni", [])
                    if sni_values:
                        node.sni_host = sni_values[0]
                    # UUID (userinfo до @)
                    if parsed.username:
                        node.uuid = urllib.parse.unquote(parsed.username)
                    # Flow (xtls-rprx-vision и т.п.)
                    flow_vals = query.get("flow", [])
                    if flow_vals:
                        node.flow = flow_vals[0]
                    # Reality: publicKey, shortId, fingerprint
                    pbk_vals = query.get("pbk", [])
                    if pbk_vals:
                        node.reality_pbk = pbk_vals[0]
                    sid_vals = query.get("sid", [])
                    if sid_vals:
                        node.reality_sid = sid_vals[0]
                    fp_vals = query.get("fp", [])
                    if fp_vals:
                        node.reality_fp = fp_vals[0]
                    # Сетевой тип (tcp / grpc / ws)
                    net_vals = query.get("type", [])
                    if net_vals:
                        node.network_type = net_vals[0]
                    return node

        except Exception:
            return None
        return None

    @classmethod
    def extract_nodes(cls, text: str, is_whitelist: bool = False) -> List[CodexNode]:
        nodes = []
        if not any(proto in text for proto in ["vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hy2://"]):
            decoded = cls.decode_b64(text)
            if any(proto in decoded for proto in ["vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hy2://"]):
                text = decoded

        for line in text.splitlines():
            line_str = line.strip()
            if line_str:
                node = cls.parse_uri(line_str, is_whitelist)
                if node:
                    nodes.append(node)
        return nodes


class CodexGeo:
    """
    // Геолокация IP без внешних зависимостей
    """
    IP_COUNTRY_MAP = {
        "45.133": ("NL", "Нидерланды", "🇳🇱"),
        "45.139": ("NL", "Нидерланды", "🇳🇱"),
        "45.194": ("ZA", "ЮАР", "🇿🇦"),
        "45.195": ("ZA", "ЮАР", "🇿🇦"),
        "45.196": ("AE", "ОАЭ", "🇦🇪"),
        "45.197": ("ZA", "ЮАР", "🇿🇦"),
        "45.198": ("US", "США", "🇺🇸"),
        "45.206": ("ZA", "ЮАР", "🇿🇦"),
        "31.76": ("DE", "Германия", "🇩🇪"),
        "185.141": ("DE", "Германия", "🇩🇪"),
        "5.188": ("FI", "Финляндия", "🇫🇮"),
        "82.40": ("GB", "Великобритания", "🇬🇧"),
        "89.34": ("DE", "Германия", "🇩🇪"),
        "154.83": ("JP", "Япония", "🇯🇵"),
        "62.60": ("DE", "Германия", "🇩🇪"),
        "152.233": ("CL", "Чили", "🇨🇱"),
        "93.114": ("RO", "Румыния", "🇷🇴"),
        "194.127": ("DE", "Германия", "🇩🇪"),
        "45.199": ("SG", "Сингапур", "🇸🇬"),
        "45.200": ("JP", "Япония", "🇯🇵"),
        "45.202": ("HK", "Гонконг", "🇭🇰"),
        "45.207": ("TW", "Тайвань", "🇹🇼"),
        "45.205": ("IN", "Индия", "🇮🇳"),
        "103.20": ("AU", "Австралия", "🇦🇺"),
        "103.172": ("HK", "Гонконг", "🇭🇰"),
        "103.21": ("US", "США", "🇺🇸"),
        "103.24": ("JP", "Япония", "🇯🇵"),
        "103.180": ("SG", "Сингапур", "🇸🇬"),
        "103.188": ("SG", "Сингапур", "🇸🇬"),
        "102.129": ("US", "США", "🇺🇸"),
        "172.93": ("US", "США", "🇺🇸"),
        "172.96": ("CA", "Канада", "🇨🇦"),
        "172.99": ("US", "США", "🇺🇸"),
        "172.104": ("JP", "Япония", "🇯🇵"),
        "172.105": ("GB", "Великобритания", "🇬🇧"),
        "172.110": ("AU", "Австралия", "🇦🇺"),
        "179.61": ("CL", "Чили", "🇨🇱"),
        "185.106": ("FI", "Финляндия", "🇫🇮"),
        "185.128": ("GB", "Великобритания", "🇬🇧"),
        "185.141": ("DE", "Германия", "🇩🇪"),
        "185.153": ("IT", "Италия", "🇮🇹"),
        "185.162": ("DE", "Германия", "🇩🇪"),
        "185.170": ("TR", "Турция", "🇹🇷"),
        "185.199": ("IR", "Иран", "🇮🇷"),
        "185.204": ("FI", "Финляндия", "🇫🇮"),
        "185.217": ("NL", "Нидерланды", "🇳🇱"),
        "185.225": ("GB", "Великобритания", "🇬🇧"),
        "185.238": ("SE", "Швеция", "🇸🇪"),
        "185.240": ("FI", "Финляндия", "🇫🇮"),
        "185.254": ("PL", "Польша", "🇵🇱"),
        "192.248": ("GB", "Великобритания", "🇬🇧"),
        "193.5": ("FI", "Финляндия", "🇫🇮"),
        "193.124": ("RU", "Россия", "🇷🇺"),
        "194.87": ("DE", "Германия", "🇩🇪"),
        "194.110": ("NL", "Нидерланды", "🇳🇱"),
        "194.127": ("DE", "Германия", "🇩🇪"),
        "194.165": ("FI", "Финляндия", "🇫🇮"),
        "195.80": ("FI", "Финляндия", "🇫🇮"),
        "195.133": ("RU", "Россия", "🇷🇺"),
        "195.154": ("FR", "Франция", "🇫🇷"),
        "195.245": ("SE", "Швеция", "🇸🇪"),
        "199.34": ("US", "США", "🇺🇸"),
        "212.113": ("SE", "Швеция", "🇸🇪"),
        "213.176": ("DE", "Германия", "🇩🇪"),
        "216.73": ("US", "США", "🇺🇸"),
        "8.210": ("HK", "Гонконг", "🇭🇰"),
        "8.218": ("HK", "Гонконг", "🇭🇰"),
        "38.58": ("US", "США", "🇺🇸"),
        "45.8": ("NL", "Нидерланды", "🇳🇱"),
        "45.9": ("DE", "Германия", "🇩🇪"),
        "45.80": ("US", "США", "🇺🇸"),
        "45.84": ("DE", "Германия", "🇩🇪"),
        "45.85": ("NL", "Нидерланды", "🇳🇱"),
        "45.87": ("DE", "Германия", "🇩🇪"),
        "45.90": ("FR", "Франция", "🇫🇷"),
        "45.91": ("US", "США", "🇺🇸"),
        "45.92": ("JP", "Япония", "🇯🇵"),
        "45.93": ("GB", "Великобритания", "🇬🇧"),
        "45.94": ("FI", "Финляндия", "🇫🇮"),
        "45.95": ("NL", "Нидерланды", "🇳🇱"),
        "45.130": ("US", "США", "🇺🇸"),
        "45.131": ("DE", "Германия", "🇩🇪"),
        "45.132": ("NL", "Нидерланды", "🇳🇱"),
        "45.133": ("NL", "Нидерланды", "🇳🇱"),
        "45.134": ("GB", "Великобритания", "🇬🇧"),
        "45.135": ("FR", "Франция", "🇫🇷"),
        "45.136": ("US", "США", "🇺🇸"),
        "45.137": ("DE", "Германия", "🇩🇪"),
        "45.138": ("JP", "Япония", "🇯🇵"),
        "45.140": ("FI", "Финляндия", "🇫🇮"),
        "45.141": ("NL", "Нидерланды", "🇳🇱"),
        "45.142": ("DE", "Германия", "🇩🇪"),
        "45.143": ("GB", "Великобритания", "🇬🇧"),
        "45.144": ("SG", "Сингапур", "🇸🇬"),
        "45.145": ("HK", "Гонконг", "🇭🇰"),
        "45.146": ("US", "США", "🇺🇸"),
        "45.147": ("CL", "Чили", "🇨🇱"),
        "45.148": ("AU", "Австралия", "🇦🇺"),
        "45.149": ("TW", "Тайвань", "🇹🇼"),
        "45.150": ("IN", "Индия", "🇮🇳"),
        "45.151": ("CA", "Канада", "🇨🇦"),
        "45.152": ("SE", "Швеция", "🇸🇪"),
        "45.153": ("IT", "Италия", "🇮🇹"),
        "45.154": ("RO", "Румыния", "🇷🇴"),
        "45.155": ("TR", "Турция", "🇹🇷"),
        "45.156": ("PL", "Польша", "🇵🇱"),
        "45.157": ("AT", "Австрия", "🇦🇹"),
        "45.158": ("ES", "Испания", "🇪🇸"),
        "45.159": ("UA", "Украина", "🇺🇦"),
        "45.160": ("BR", "Бразилия", "🇧🇷"),
        "45.161": ("ZA", "ЮАР", "🇿🇦"),
        "45.162": ("AR", "Аргентина", "🇦🇷"),
        "45.163": ("MX", "Мексика", "🇲🇽"),
        "45.164": ("NZ", "Новая Зеландия", "🇳🇿"),
        "45.165": ("IL", "Израиль", "🇮🇱"),
        "45.166": ("PK", "Пакистан", "🇵🇰"),
        "45.167": ("KR", "Южная Корея", "🇰🇷"),
        "45.168": ("TH", "Таиланд", "🇹🇭"),
        "45.169": ("VN", "Вьетнам", "🇻🇳"),
        "45.170": ("CO", "Колумбия", "🇨🇴"),
        "45.171": ("NG", "Нигерия", "🇳🇬"),
        "45.172": ("KE", "Кения", "🇰🇪"),
        "45.173": ("EG", "Египет", "🇪🇬"),
        "45.174": ("BD", "Бангладеш", "🇧🇩"),
        "45.175": ("PH", "Филиппины", "🇵🇭"),
        "45.176": ("MY", "Малайзия", "🇲🇾"),
        "45.177": ("ID", "Индонезия", "🇮🇩"),
        "45.178": ("CZ", "Чехия", "🇨🇿"),
        "45.179": ("CH", "Швейцария", "🇨🇭"),
        "45.180": ("PT", "Португалия", "🇵🇹"),
        "45.181": ("BE", "Бельгия", "🇧🇪"),
        "45.182": ("DK", "Дания", "🇩🇰"),
        "45.183": ("NO", "Норвегия", "🇳🇴"),
        "45.184": ("IE", "Ирландия", "🇮🇪"),
        "45.185": ("GR", "Греция", "🇬🇷"),
        "45.186": ("HU", "Венгрия", "🇭🇺"),
        "45.187": ("SK", "Словакия", "🇸🇰"),
        "45.188": ("BG", "Болгария", "🇧🇬"),
        "45.189": ("HR", "Хорватия", "🇭🇷"),
        "45.190": ("RS", "Сербия", "🇷🇸"),
        "45.191": ("LT", "Литва", "🇱🇹"),
        "45.192": ("LV", "Латвия", "🇱🇻"),
        "45.193": ("EE", "Эстония", "🇪🇪"),
        "2.27": ("GB", "Великобритания", "🇬🇧"),
        "5.45": ("RU", "Россия", "🇷🇺"),
        "5.255": ("RU", "Россия", "🇷🇺"),
        "31.77": ("DE", "Германия", "🇩🇪"),
        "45.12": ("RU", "Россия", "🇷🇺"),
        "66.234": ("US", "США", "🇺🇸"),
        "77.88": ("RU", "Россия", "🇷🇺"),
        "83.147": ("RU", "Россия", "🇷🇺"),
        "84.17": ("CH", "Швейцария", "🇨🇭"),
        "84.201": ("RU", "Россия", "🇷🇺"),
        "87.249": ("RU", "Россия", "🇷🇺"),
        "90.156": ("RU", "Россия", "🇷🇺"),
        "93.158": ("RU", "Россия", "🇷🇺"),
        "95.173": ("RU", "Россия", "🇷🇺"),
        "100.43": ("RU", "Россия", "🇷🇺"),
        "144.31": ("US", "США", "🇺🇸"),
        "154.222": ("JP", "Япония", "🇯🇵"),
        "158.160": ("RU", "Россия", "🇷🇺"),
        "161.97": ("NL", "Нидерланды", "🇳🇱"),
        "168.222": ("RU", "Россия", "🇷🇺"),
        "176.109": ("RU", "Россия", "🇷🇺"),
        "178.154": ("RU", "Россия", "🇷🇺"),
        "185.185": ("RU", "Россия", "🇷🇺"),
        "185.86": ("RU", "Россия", "🇷🇺"),
        "194.5": ("RU", "Россия", "🇷🇺"),
        "194.55": ("RU", "Россия", "🇷🇺"),
        "199.21": ("RU", "Россия", "🇷🇺"),
        "212.233": ("RU", "Россия", "🇷🇺"),
        "213.180": ("RU", "Россия", "🇷🇺"),
        "213.219": ("RU", "Россия", "🇷🇺"),
        "178.250": ("DE", "Германия", "🇩🇪"),
        "185.22": ("RU", "Россия", "🇷🇺"),
        "185.229": ("TR", "Турция", "🇹🇷"),
        "185.241": ("FI", "Финляндия", "🇫🇮"),
        "194.58": ("RU", "Россия", "🇷🇺"),
        "213.226": ("DE", "Германия", "🇩🇪"),
        "216.106": ("US", "США", "🇺🇸"),
    }

    DEFAULT_COUNTRY = ("XX", "Неизвестно", "🌐")

    @staticmethod
    def flag_from_code(cc: str) -> str:
        """Флаг-эмодзи из двухбуквенного кода страны (Regional Indicator Symbols)."""
        if not cc or len(cc) != 2 or not cc.isalpha():
            return "🌐"
        cc = cc.upper()
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc)

    # // SNI -> страна (для серверов обхода, чей IP принадлежит CDN/облаку)
    SNI_COUNTRY_MAP = {
        "ru": ("RU", "Россия"),
        "yandex.ru": ("RU", "Россия"),
        "ya.ru": ("RU", "Россия"),
        "max.ru": ("RU", "Россия"),
        "ok.ru": ("RU", "Россия"),
        "vk.com": ("RU", "Россия"),
        "mail.ru": ("RU", "Россия"),
        "webmax.ru": ("RU", "Россия"),
        "api-maps.yandex.ru": ("RU", "Россия"),
        "storage.yandex.net": ("RU", "Россия"),
        "sso.passport.yandex.ru": ("RU", "Россия"),
        "auto.api-yandex.net": ("RU", "Россия"),
        "cloud.mail.ru": ("RU", "Россия"),
        "eh.vk.com": ("RU", "Россия"),
        "api.ok.ru": ("RU", "Россия"),
        "api.yandex.net": ("RU", "Россия"),
    }

    @classmethod
    def country_from_sni(cls, sni: str) -> Tuple[str, str]:
        if not sni:
            return ("", "")
        sni = sni.lower()
        for key, (cc, name) in cls.SNI_COUNTRY_MAP.items():
            if sni == key or sni.endswith("." + key) or key in sni:
                return (cc, name)
        # // По TLD: .ru/.su/.by -> RU-зона (для белых списков это почти всегда RU)
        if sni.endswith(".ru") or sni.endswith(".su") or sni.endswith(".by"):
            return ("RU", "Россия")
        return ("", "")

    @classmethod
    def detect(cls, ip: str) -> Tuple[str, str, str]:
        if not ip:
            return cls.DEFAULT_COUNTRY
        parts = ip.split(".")
        if len(parts) < 2:
            return cls.DEFAULT_COUNTRY
        key2 = f"{parts[0]}.{parts[1]}"
        if key2 in cls.IP_COUNTRY_MAP:
            return cls.IP_COUNTRY_MAP[key2]
        key3 = f"{parts[0]}.{parts[1]}.{parts[2]}"
        if key3 in cls.IP_COUNTRY_MAP:
            return cls.IP_COUNTRY_MAP[key3]
        return cls.DEFAULT_COUNTRY

    @classmethod
    def enrich_online(cls, nodes: List["CodexNode"], timeout: float = 8.0):
        """
        // Онлайн-геолокация через ip-api.com (батчами) для серверов,
        // которые офлайн-словарь не определил (XX). Работает только для
        // финальных ~50 серверов, поэтому нагрузка минимальна. При ошибке
        // сети молча оставляем XX (офлайн-словарь — запасной вариант).
        """
        unknown = [n for n in nodes if n.country_code in ("", "XX")]
        if not unknown:
            return

        # Батч по 40 IP (лимит free-тарифа ip-api ~45 запросов/мин)
        batch_size = 40
        for i in range(0, len(unknown), batch_size):
            chunk = unknown[i:i + batch_size]
            payload = json.dumps([{"query": n.host} for n in chunk]).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                for item, node in zip(data, chunk):
                    if isinstance(item, dict) and item.get("status") == "success":
                        cc = (item.get("countryCode") or "XX").upper()
                        name = item.get("country") or "Неизвестно"
                        node.country_code = cc
                        node.country_name = name
                        node.country_flag = cls.flag_from_code(cc)
            except Exception:
                # Сеть недоступна (например, ip-api заблокирован) — оставляем XX
                return


class CodexRenamer:
    """
    // Оформление понятных и красивых названий для клиента HApp
    """
    @staticmethod
    def apply_happ_name(node: CodexNode, index: int) -> str:
        # // Страна уже определена заранее (offline-словарь + онлайн ip-api)
        # // в generate_top50. Здесь только подставляем и обрабатываем локальный прокси.
        if node.host in ("127.0.0.1", "localhost", "::1"):
            cc, cname, cflag = ("LOCAL", "Локальный", "🖥️")
        else:
            cc, cname, cflag = node.country_code or "XX", node.country_name or "Неизвестно", node.country_flag or "🌐"
        node.country_code = cc
        node.country_name = cname
        node.country_flag = cflag

        # // Формирование метки с флагом и страной
        prefix_icon = "⚡" if node.is_whitelist else "🚀"
        proto_tag = node.protocol.upper()
        ping_tag = f"{int(node.latency_ms)}ms" if node.latency_ms else "OK"

        # // Итоговое имя в HApp: "⚡ [01] 🇩🇪 DE | VLESS (29ms)"
        display_name = f"{prefix_icon} [{index:02d}] {cflag} {cc} | {proto_tag} ({ping_tag})"

        uri = node.raw_uri.strip()

        if uri.startswith("vmess://"):
            try:
                b64_part = uri[8:].split("#")[0].split("?")[0]
                data = json.loads(CodexParser.decode_b64(b64_part))
                data["ps"] = display_name
                new_b64 = base64.b64encode(json.dumps(data, ensure_ascii=False).encode("utf-8")).decode("utf-8")
                return "vmess://" + new_b64
            except Exception:
                return uri
        else:
            base_part = uri.split("#")[0]
            encoded_name = urllib.parse.quote(display_name)
            return f"{base_part}#{encoded_name}"


class CodexFastProbe:
    """
    // Сверхбыстрый асинхронный зонд: реальный TLS-хендшейк к SNI-хосту.
    // Простого TCP-коннекта недостаточно — "зомби"-серверы принимают соединение,
    // но не отвечают по TLS, поэтому трафик не идёт. Хендшейк = настоящая живость.
    """
    def __init__(self, timeout: float = 1.3, concurrency: int = 400, require_tls: bool = True):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.require_tls = require_tls
        self.ssl_ctx = self._build_ssl_ctx()

    @staticmethod
    def _build_ssl_ctx():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def probe(self, node: CodexNode) -> CodexNode:
        async with self.semaphore:
            start = time.perf_counter()
            # // Этап 1: реальный TLS-хендшейк к SNI-хосту (сильный сигнал живости)
            try:
                sni = node.sni_host or node.host
                conn = asyncio.open_connection(
                    node.host, node.port,
                    ssl=self.ssl_ctx, server_hostname=sni,
                )
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                node.latency_ms = (time.perf_counter() - start) * 1000.0
                node.is_alive = True
                node.tls_verified = True
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return node
            except Exception:
                pass

            # // Этап 2: TLS не прошёл. Если не требуем строго TLS — пробуем
            # // обычный TCP-коннект (слабый сигнал: зомби-серверы тоже примут).
            if not self.require_tls:
                try:
                    start2 = time.perf_counter()
                    conn = asyncio.open_connection(node.host, node.port)
                    reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                    node.latency_ms = (time.perf_counter() - start2) * 1000.0
                    node.is_alive = True
                    node.tls_verified = False
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return node
                except Exception:
                    pass

            node.is_alive = False
            return node

    async def probe_all(self, nodes: List[CodexNode], label: str = "Узлы") -> List[CodexNode]:
        total = len(nodes)
        if total == 0:
            return []
        
        print(f"[*] Зондирование пула '{label}' ({total} серверов)...")
        tasks = [asyncio.create_task(self.probe(n)) for n in nodes]
        results = await asyncio.gather(*tasks)
        alive = [n for n in results if n.is_alive]
        # TLS-верифицированные — впереди (это реально живые); TCP-зомби — в конце
        alive.sort(key=lambda x: (0 if getattr(x, "tls_verified", False) else 1, x.latency_ms if x.latency_ms is not None else 99999))
        print(f"    -> Доступных серверов: {len(alive)} из {total}")
        return alive


class CodexRealProbe:
    """
    // Проверка живости РЕАЛЬНЫМ VLESS+Reality подключением через xray-core.
    // TLS-зонд даёт ложные срабатывания (Reality всегда отвечает на TLS),
    // поэтому единственный честный тест — заставить xray-core реально
    // подключиться и измерить пинг через встроенный observatory.
    """

    API_PORT = 19876

    def __init__(self, xray_bin: str = "xray", probe_url: str = "http://www.gstatic.com/generate_204", timeout: float = 12.0):
        self.xray_bin = xray_bin
        self.probe_url = probe_url
        self.timeout = timeout

    def _build_outbound(self, node: CodexNode, tag: str) -> dict:
        """Формирует outbounds-блок xray для VLESS/Trojan с Reality."""
        user = {
            "id": node.uuid or "",
            "encryption": "none",
        }
        if node.flow:
            user["flow"] = node.flow

        stream_settings = {
            "network": node.network_type or "tcp",
        }

        # // Reality
        if node.reality_pbk:
            stream_settings["security"] = "reality"
            reality = {
                "serverName": node.sni_host or "",
                "publicKey": node.reality_pbk,
                "fingerprint": node.reality_fp or "chrome",
            }
            if node.reality_sid:
                reality["shortId"] = node.reality_sid
            stream_settings["realitySettings"] = reality

        # // gRPC serviceName
        if (node.network_type or "tcp") == "grpc":
            svc = urllib.parse.parse_qs(urllib.parse.urlparse(node.raw_uri).query.replace("&amp;", "&")).get("serviceName", [""])
            stream_settings["grpcSettings"] = {"serviceName": svc[0] if svc else ""}

        return {
            "tag": tag,
            "protocol": node.protocol,
            "settings": {
                "vnext": [{
                    "address": node.host,
                    "port": node.port,
                    "users": [user],
                }]
            },
            "streamSettings": stream_settings,
        }

    async def probe_all(self, nodes: List[CodexNode]) -> List[CodexNode]:
        """
        Возвращает только РЕАЛЬНО живые серверы с измеренным пингом.
        Серверы, которые принимают TLS, но не проксируют — отсеются.
        """
        nodes = [n for n in nodes if n.host and n.port and n.uuid]
        if not nodes:
            return []

        tags = [f"p{i}" for i in range(len(nodes))]
        outbounds = [self._build_outbound(n, t) for n, t in zip(nodes, tags)]

        api_tag = "api"
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "tag": api_tag,
                    "port": self.API_PORT,
                    "listen": "127.0.0.1",
                    "protocol": "dokodemo-door",
                    "settings": {"address": "127.0.0.1"},
                }
            ],
            "outbounds": outbounds,
            "routing": {
                "rules": [{"inboundTag": [api_tag], "outboundTag": api_tag}],
            },
            "api": {
                "services": ["ObservatoryService"],
                "tag": api_tag,
            },
            "observatory": {
                "subjectSelector": tags,
                "probeURL": self.probe_url,
                "probeInterval": "2s",
                "enableConcurrency": True,
            },
        }

        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_xray_probe_config.json")
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False)

            # // Запускаем xray в фоне
            proc = await asyncio.create_subprocess_exec(
                self.xray_bin, "run", "-c", config_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                # // Ждём, пока observatory соберёт данные
                await asyncio.sleep(min(self.timeout, 5.0))

                # // Опрос через xray api CLI
                res = await asyncio.create_subprocess_exec(
                    self.xray_bin, "api", "ObservatoryService.GetOutboundsStatus",
                    "--server", f"127.0.0.1:{self.API_PORT}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(res.communicate(), timeout=10)
                return self._parse_observatory(stdout.decode("utf-8", errors="ignore"), nodes, tags)
            finally:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
        except Exception:
            return []
        finally:
            try:
                os.remove(config_path)
            except Exception:
                pass

    def _parse_observatory(self, output: str, nodes: List[CodexNode], tags: List[str]) -> List[CodexNode]:
        """Парсит вывод xray api ObservatoryService и возвращает живые серверы."""
        alive = []
        try:
            data = json.loads(output)
        except Exception:
            return []

        # // Формат ответа xray: { "status": [ { "alive": true, "delay": 123, "outboundTag": "p0" } ] }
        status_list = []
        if isinstance(data, dict):
            for key in ("status", "outboundStatus", "probe", "targets"):
                status_list = data.get(key, [])
                if status_list:
                    break

        tag_to_node = {t: n for t, n in zip(tags, nodes)}
        for item in status_list:
            if not isinstance(item, dict):
                continue
            tag = item.get("outboundTag") or item.get("tag") or ""
            node = tag_to_node.get(tag)
            if not node:
                continue
            is_alive = item.get("alive", False)
            delay = item.get("delay", 0)
            if is_alive and delay and delay > 0:
                node.is_alive = True
                node.latency_ms = float(delay)
                node.tls_verified = True
                alive.append(node)

        alive.sort(key=lambda x: x.latency_ms if x.latency_ms is not None else 99999)
        return alive
    """
    // Главный строитель подписки HApp и локальный сервер раздачи
    """
    def __init__(self, repo_dir: str = "configs_repo/githubmirror", out_dir: str = "."):
        self.repo_dir = repo_dir
        self.out_dir = out_dir

    def load_nodes(self) -> Tuple[List[CodexNode], List[CodexNode]]:
        whitelist_nodes: List[CodexNode] = []
        global_nodes: List[CodexNode] = []
        seen_keys: Set[str] = set()

        # // 1. Читаем специальный архив белых списков (26.txt)
        wl_path = os.path.join(self.repo_dir, "26.txt")
        if os.path.exists(wl_path):
            with open(wl_path, "r", encoding="utf-8", errors="ignore") as f:
                for n in CodexParser.extract_nodes(f.read(), is_whitelist=True):
                    k = n.key()
                    if k not in seen_keys:
                        seen_keys.add(k)
                        whitelist_nodes.append(n)

        # // 2. Считываем зеркала со 2 по 25, отбирая из каждого живые и разнообразные узлы
        active_mirrors = [3, 2, 10, 12, 14, 19, 21, 24, 11, 13, 15, 17, 18, 20, 22, 23, 25, 4, 5, 6, 7, 8, 9]
        for i in active_mirrors:
            fpath = os.path.join(self.repo_dir, f"{i}.txt")
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        file_nodes = CodexParser.extract_nodes(f.read(), is_whitelist=False)
                    added = 0
                    for n in file_nodes:
                        k = n.key()
                        if k not in seen_keys:
                            seen_keys.add(k)
                            global_nodes.append(n)
                            added += 1
                            if added >= 80:  # берем по 80 лучших узлов из каждого зеркала
                                break
                except Exception:
                    pass

        print(f"[+] Извлечено из локального хранилища:")
        print(f"    - Серверов белых списков: {len(whitelist_nodes)}")
        print(f"    - Глобальных скоростных узлов: {len(global_nodes)}")
        return whitelist_nodes, global_nodes

    async def generate_top50(self, wl_count: int = 25, global_count: int = 25, timeout: float = 1.3,
                              max_latency: float = 800.0, require_tls: bool = True,
                              xray_bin: str = "xray", use_real_probe: bool = True) -> List[CodexNode]:
        wl_raw, global_raw = self.load_nodes()
        probe = CodexFastProbe(timeout=timeout, concurrency=400, require_tls=require_tls)

        # Ограничиваем выборку для экспресс-проверки
        wl_pool = wl_raw[:1500] if len(wl_raw) > 1500 else wl_raw
        global_pool = global_raw[:1500] if len(global_raw) > 1500 else global_raw

        # Параллельная проверка обоих пулов
        alive_wl, alive_global = await asyncio.gather(
            probe.probe_all(wl_pool, label="Белые Списки (SNI/CIDR)"),
            probe.probe_all(global_pool, label="Глобальная Скорость")
        )

        # TLS-префильтр: берём больше кандидатов, чем нужно в итог —
        # реальный xray-зонд отсевёт тех, кто принимает TLS, но не проксирует.
        candidate_wl = alive_wl[:120]
        candidate_gl = alive_global[:120]
        candidates = candidate_wl + candidate_gl

        # // РЕАЛЬНАЯ проверка через xray-core (честный тест)
        real_alive: List[CodexNode] = []
        if use_real_probe and candidates:
            print(f"[*] Реальная проверка через xray-core ({len(candidates)} кандидатов)...")
            real_probe = CodexRealProbe(xray_bin=xray_bin, timeout=12.0)
            real_alive = await real_probe.probe_all(candidates)
            print(f"    -> Реально рабочих серверов: {len(real_alive)}")

        # // Fallback: если xray недоступен (нет бинарника) — используем TLS-фильтр
        if not real_alive:
            if use_real_probe:
                print("[!] xray-core недоступен или не нашёл рабочих — используем TLS-префильтр")
            LATENCY_DEAD_THRESHOLD_MS = max_latency
            real_alive = [n for n in candidates if n.latency_ms and n.latency_ms < LATENCY_DEAD_THRESHOLD_MS]

        # // Разделяем обратно на белые списки и глобальные, сортируем по реальному пингу
        real_wl = [n for n in real_alive if n.is_whitelist][:wl_count]
        real_gl = [n for n in real_alive if not n.is_whitelist][:global_count]

        # Объединяем в итоговый ТОП-50: белые списки первыми
        combined: List[CodexNode] = real_wl + real_gl

        # // Геолокация: сначала офлайн-словарь, затем онлайн ip-api для XX
        for n in combined:
            if n.host not in ("127.0.0.1", "localhost", "::1"):
                cc, cname, cflag = CodexGeo.detect(n.host)
                n.country_code, n.country_name, n.country_flag = cc, cname, cflag
                # // Если офлайн-словарь не определил (XX), пробуем вывести
                # // страну из SNI (yandex/ya.ru/max.ru/vk.com -> RU и т.п.)
                if cc == "XX" and n.sni_host:
                    scc, scname = CodexGeo.country_from_sni(n.sni_host)
                    if scc:
                        n.country_code = scc
                        n.country_name = scname
                        n.country_flag = CodexGeo.flag_from_code(scc)
        CodexGeo.enrich_online(combined)

        # // Присваиваем понятные имена с флагами
        for idx, node in enumerate(combined, 1):
            node.formatted_uri = CodexRenamer.apply_happ_name(node, idx)

        # Сохранение файлов подписки
        self.save_artifacts(combined)
        return combined

    def save_artifacts(self, top_nodes: List[CodexNode]):
        os.makedirs(self.out_dir, exist_ok=True)
        
        # 1. Прямой список ссылок с красивыми именами для вставки в HApp / V2Ray
        plain_path = os.path.join(self.out_dir, "happ_subscription.txt")
        with open(plain_path, "w", encoding="utf-8") as f:
            for n in top_nodes:
                f.write(n.formatted_uri + "\n")

        # 2. Base64 подписка (стандартный формат URL-подписок)
        b64_path = os.path.join(self.out_dir, "happ_subscription_b64.txt")
        raw_text = "\n".join(n.formatted_uri for n in top_nodes)
        b64_data = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(b64_data)

        # 3. JSON для приложений
        json_path = os.path.join(self.out_dir, "happ_subscription.json")
        data = {
            "title": "HApp Top 50 Codex Subscription",
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_nodes": len(top_nodes),
            "whitelist_nodes": len([n for n in top_nodes if n.is_whitelist]),
            "global_nodes": len([n for n in top_nodes if not n.is_whitelist]),
            "nodes": [
                {
                    "type": "whitelist" if n.is_whitelist else "global",
                    "protocol": n.protocol,
                    "host": n.host,
                    "port": n.port,
                    "ping_ms": round(n.latency_ms, 1) if n.latency_ms else None,
                    "country_code": n.country_code,
                    "country_name": n.country_name,
                    "country_flag": n.country_flag,
                    "sni": n.sni_host,
                    "uri": n.formatted_uri
                }
                for n in top_nodes
            ]
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        print("\n" + "=" * 65)
        print("СФОРМИРОВАНА ЕДИНАЯ ПОДПИСКА ТОП-50 ДЛЯ HAPP:")
        print(f"  [+] Серверов Белых Списков:   {len([n for n in top_nodes if n.is_whitelist])}")
        print(f"  [+] Скоростных серверов:      {len([n for n in top_nodes if not n.is_whitelist])}")
        print(f"  -> Прямой список (Plain):     {os.path.abspath(plain_path)}")
        print(f"  -> Подписка Base64 (URL/Sub): {os.path.abspath(b64_path)}")
        print("=" * 65)

    def load_subscription_servers(self) -> List[CodexNode]:
        """Загружает серверы из текущей подписки (happ_subscription.json)."""
        json_path = os.path.join(self.out_dir, "happ_subscription.json")
        if not os.path.exists(json_path):
            return []
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            nodes = []
            for entry in data.get("nodes", []):
                uri = entry.get("uri", "")
                if uri:
                    node = CodexParser.parse_uri(uri, is_whitelist=(entry.get("type") == "whitelist"))
                    if node:
                        nodes.append(node)
            return nodes
        except Exception:
            return []

    async def find_replacements(self, count: int, xray_bin: str, exclude_keys: set, require_tls: bool = False) -> List[CodexNode]:
        """Ищет живые замены из пула конфигов, исключая уже используемые серверы."""
        wl_raw, global_raw = self.load_nodes()
        candidates = [n for n in (wl_raw + global_raw) if n.key() not in exclude_keys]
        # // Тестируем кандидатов реальным xray-зондом батчами по 100
        real_probe = CodexRealProbe(xray_bin=xray_bin, timeout=12.0)
        found: List[CodexNode] = []
        batch_size = 100
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            alive = await real_probe.probe_all(batch)
            found.extend(alive)
            if len(found) >= count:
                break
        return found[:count]

    async def watch_cycle(self, xray_bin: str = "xray", require_tls: bool = False) -> List[CodexNode]:
        """
        Один цикл проверки: тестирует серверы текущей подписки реальным xray-коннектом,
        мёртвые заменяет живыми из пула. Возвращает итоговый список серверов.
        """
        current = self.load_subscription_servers()
        if not current:
            print("[!] Подписка пуста — генерирую начальную...")
            return await self.generate_top50(use_real_probe=True, xray_bin=xray_bin, require_tls=require_tls)

        print(f"[*] Проверка {len(current)} серверов подписки (xray real probe)...")
        real_probe = CodexRealProbe(xray_bin=xray_bin, timeout=12.0)
        alive = await real_probe.probe_all(current)
        dead_count = len(current) - len(alive)

        if dead_count == 0:
            print(f"    ✓ Все {len(current)} серверов живые — замен не нужно")
            for idx, node in enumerate(alive, 1):
                node.formatted_uri = CodexRenamer.apply_happ_name(node, idx)
            self.save_artifacts(alive)
            return alive

        print(f"    ✗ Мёртвых серверов: {dead_count} из {len(current)}")
        exclude = {n.key() for n in alive}
        replacements = await self.find_replacements(dead_count, xray_bin, exclude, require_tls)
        if replacements:
            print(f"    → Найдено замен: {len(replacements)}")
            combined = alive + replacements
        else:
            print(f"    ! Не найдено замен — оставляю {len(alive)} живых")
            combined = alive

        for idx, node in enumerate(combined, 1):
            node.formatted_uri = CodexRenamer.apply_happ_name(node, idx)
        self.save_artifacts(combined)
        print(f"    ✓ Подписка обновлена: {len(combined)} серверов")
        return combined

    async def watch_loop(self, interval_minutes: int = 5, xray_bin: str = "xray", require_tls: bool = False):
        """
        Бесконечный цикл: проверяет серверы текущей подписки реальным xray-коннектом,
        мёртвые заменяет живыми из пула. Интервал по умолчанию — 5 минут.
        """
        print(f"\n[+] РЕЖИМ ПРОВЕРКИ ПОДПИСКИ каждые {interval_minutes} минут (xray real probe)")
        print("    Ctrl+C для остановки.\n")

        while True:
            try:
                await self.watch_cycle(xray_bin=xray_bin, require_tls=require_tls)
            except Exception as e:
                print(f"    ! Ошибка в цикле: {e}")
            await asyncio.sleep(interval_minutes * 60)


# // Встроенный сверхлегкий HTTP-сервер раздачи подписки по локальной сети
class CodexHttpHandler(http.server.BaseHTTPRequestHandler):
    hub_instance: Optional[HappSubscriptionHub] = None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/sub", "/happ", "/subscription", "/"):
            b64_file = os.path.join(self.hub_instance.out_dir, "happ_subscription_b64.txt")
            if not os.path.exists(b64_file):
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"Subscription not generated yet. Please wait.")
                return

            with open(b64_file, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", "attachment; filename=\"happ_sub.txt\"")
            # Заголовки для HApp/V2Ray клиентов об интервале обновления (6 часов)
            self.send_header("profile-update-interval", "6")
            self.send_header("subscription-userinfo", "upload=0; download=0; total=107374182400; expire=0")
            self.end_headers()
            self.wfile.write(content)
        elif path == "/plain":
            plain_file = os.path.join(self.hub_instance.out_dir, "happ_subscription.txt")
            with open(plain_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Тихий режим логов для экономии ресурсов
        pass


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_http_server(hub: HappSubscriptionHub, port: int = 2080):
    CodexHttpHandler.hub_instance = hub
    server = http.server.HTTPServer(("0.0.0.0", port), CodexHttpHandler)
    local_ip = get_local_ip()
    print(f"\n[+] СЕРВЕР ПОДПИСКИ ДЛЯ HAPP АКТИВЕН:")
    print(f"    Локальный URL (на этом ПК):      http://127.0.0.1:{port}/sub")
    print(f"    URL для Телефона (в той же Wi-Fi): http://{local_ip}:{port}/sub")
    print(f"    (В HApp на смартфоне вставьте этот URL в поле добавления подписки)\n")
    server.serve_forever()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="HApp Top-50 Subscription Hub & Whitelist Checker")
    parser.add_argument("--update", action="store_true", help="Только сгенерировать подписку ТОП-50 и выйти")
    parser.add_argument("--serve", action="store_true", help="Запустить локальный микросервер раздачи подписки")
    parser.add_argument("--port", type=int, default=2080, help="Порт микросервера (по умолчанию 2080)")
    parser.add_argument("--auto-refresh", type=int, default=0, help="Период автообновления серверов в минутах (0 = выключено)")
    parser.add_argument("--timeout", type=float, default=1.3, help="Таймаут проверки отклика (по умолчанию 1.3с)")
    parser.add_argument("--max-latency", type=float, default=800.0, help="Порог отсечения дохлых серверов в мс (по умолчанию 800мс)")
    parser.add_argument("--require-tls", dest="require_tls", action="store_true", default=False, help="Строго требовать TLS-хендшейк (максимально отсекает дохлых, но может дать меньше серверов)")
    parser.add_argument("--no-require-tls", dest="require_tls", action="store_false", help="Гибрид: TLS-проверка с TCP-фолбэком, TLS-вериф. серверы в приоритете (по умолчанию)")
    parser.add_argument("--xray-bin", type=str, default="xray", help="Путь к xray-core бинарнику (по умолчанию 'xray')")
    parser.add_argument("--no-real-probe", action="store_true", help="Отключить реальную проверку xray-core (только TLS-фильтр)")
    parser.add_argument("--watch", action="store_true", help="Режим проверки подписки: каждые N минут тестирует серверы и заменяет мёртвые живыми")
    parser.add_argument("--watch-once", action="store_true", help="Один цикл проверки (для GitHub Action), затем выход")
    parser.add_argument("--interval", type=int, default=5, help="Интервал проверки в минутах для --watch (по умолчанию 5)")

    args = parser.parse_args()
    hub = HappSubscriptionHub()

    # // Режим непрерывной проверки подписки (локально)
    if args.watch:
        asyncio.run(hub.watch_loop(interval_minutes=args.interval, xray_bin=args.xray_bin, require_tls=args.require_tls))
        return

    # // Один цикл проверки (для GitHub Action)
    if args.watch_once:
        asyncio.run(hub.watch_cycle(xray_bin=args.xray_bin, require_tls=args.require_tls))
        return

    # Генерация подписки ТОП-50
    asyncio.run(hub.generate_top50(wl_count=25, global_count=25, timeout=args.timeout,
                                   max_latency=args.max_latency, require_tls=args.require_tls,
                                   xray_bin=args.xray_bin, use_real_probe=not args.no_real_probe))

    if args.serve or (not args.update):
        if args.auto_refresh > 0:
            def refresh_worker():
                while True:
                    time.sleep(args.auto_refresh * 60)
                    print(f"[*] Автообновление ТОП-50 подписки...")
                    asyncio.run(hub.generate_top50(wl_count=25, global_count=25, timeout=args.timeout,
                                                   max_latency=args.max_latency, require_tls=args.require_tls,
                                                   xray_bin=args.xray_bin, use_real_probe=not args.no_real_probe))
            t = threading.Thread(target=refresh_worker, daemon=True)
            t.start()

        run_http_server(hub, port=args.port)


if __name__ == "__main__":
    main()
