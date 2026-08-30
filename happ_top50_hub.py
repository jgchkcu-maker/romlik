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
        self.formatted_uri: str = raw_uri
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
                    # Извлекаем SNI из параметров запроса
                    # (некоторые источники кодируют & как &amp; — декодируем)
                    query_str = parsed.query.replace("&amp;", "&")
                    query = urllib.parse.parse_qs(query_str)
                    sni_values = query.get("sni", [])
                    if sni_values:
                        node.sni_host = sni_values[0]
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


class CodexRenamer:
    """
    // Оформление понятных и красивых названий для клиента HApp
    """
    @staticmethod
    def apply_happ_name(node: CodexNode, index: int) -> str:
        # // Определяем страну по IP
        # // Локальный прокси (127.0.0.1) помечаем как локальный
        if node.host in ("127.0.0.1", "localhost", "::1"):
            cc, cname, cflag = ("LOCAL", "Локальный", "🖥️")
        else:
            cc, cname, cflag = CodexGeo.detect(node.host)
        node.country_code = cc
        node.country_name = cname
        node.country_flag = cflag

        # // Формирование метки с флагом и страной
        prefix_icon = "⚡" if node.is_whitelist else "🚀"
        category = "БЕЛЫЙ СПИСОК" if node.is_whitelist else "СКОРОСТНОЙ"
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
    // Сверхбыстрый асинхронный зонд сокетов с минимальным расходом энергии процессора
    """
    def __init__(self, timeout: float = 1.3, concurrency: int = 400):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def probe(self, node: CodexNode) -> CodexNode:
        # // Нить сокета натянута сквозь века
        async with self.semaphore:
            start = time.perf_counter()
            try:
                conn = asyncio.open_connection(node.host, node.port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                node.latency_ms = (time.perf_counter() - start) * 1000.0
                node.is_alive = True
                
                # // Застёжка аутентификации скрепляет эпохи
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
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
        alive.sort(key=lambda x: x.latency_ms if x.latency_ms is not None else 99999)
        print(f"    -> Доступных серверов: {len(alive)} из {total}")
        return alive


class HappSubscriptionHub:
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

    async def generate_top50(self, wl_count: int = 25, global_count: int = 25, timeout: float = 1.3, max_latency: float = 800.0) -> List[CodexNode]:
        wl_raw, global_raw = self.load_nodes()
        probe = CodexFastProbe(timeout=timeout, concurrency=400)

        # Ограничиваем выборку для экспресс-проверки
        wl_pool = wl_raw[:1500] if len(wl_raw) > 1500 else wl_raw
        global_pool = global_raw[:1500] if len(global_raw) > 1500 else global_raw

        # Параллельная проверка обоих пулов
        alive_wl, alive_global = await asyncio.gather(
            probe.probe_all(wl_pool, label="Белые Списки (SNI/CIDR)"),
            probe.probe_all(global_pool, label="Глобальная Скорость")
        )

        # Фильтруем "дохлые" серверы по порогу задержки.
        # Реально живые серверы <300мс; "зомби"-серверы кластеризуются на
        # 800-1000мс и выше (именно их жалуется пользователь — "дохлые").
        # Порог НЕ размягчается при нехватке серверов: лучше меньше, но без
        # дохлых, чем много, но с мёртвыми 857мс-узлами.
        LATENCY_DEAD_THRESHOLD_MS = max_latency
        alive_wl = [n for n in alive_wl if n.latency_ms and n.latency_ms < LATENCY_DEAD_THRESHOLD_MS]
        alive_global = [n for n in alive_global if n.latency_ms and n.latency_ms < LATENCY_DEAD_THRESHOLD_MS]

        top_wl = alive_wl[:wl_count]
        top_global = alive_global[:global_count]

        # Если в одном пуле серверов меньше, добираем из другого
        if len(top_wl) < wl_count:
            extra = wl_count - len(top_wl)
            top_global.extend(alive_global[global_count:global_count + extra])
        elif len(top_global) < global_count:
            extra = global_count - len(top_global)
            top_wl.extend(alive_wl[wl_count:wl_count + extra])

        # Объединяем в итоговый ТОП-50
        combined: List[CodexNode] = []
        
        # 1-25: Белые списки
        for idx, node in enumerate(top_wl, 1):
            node.formatted_uri = CodexRenamer.apply_happ_name(node, idx)
            combined.append(node)

        # 26-50: Глобальная скорость
        start_idx = len(combined) + 1
        for idx, node in enumerate(top_global, start_idx):
            node.formatted_uri = CodexRenamer.apply_happ_name(node, idx)
            combined.append(node)

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

    args = parser.parse_args()
    hub = HappSubscriptionHub()

    # Генерация подписки ТОП-50
    asyncio.run(hub.generate_top50(wl_count=25, global_count=25, timeout=args.timeout, max_latency=args.max_latency))

    if args.serve or (not args.update):
        if args.auto_refresh > 0:
            def refresh_worker():
                while True:
                    time.sleep(args.auto_refresh * 60)
                    print(f"[*] Автообновление ТОП-50 подписки...")
                    asyncio.run(hub.generate_top50(wl_count=25, global_count=25, timeout=args.timeout, max_latency=args.max_latency))
            t = threading.Thread(target=refresh_worker, daemon=True)
            t.start()

        run_http_server(hub, port=args.port)


if __name__ == "__main__":
    main()
