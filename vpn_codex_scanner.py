#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===============================================================================
КОДЕКС АРХИВА «ПОСЛЕДНИЙ КОДЕКС» // ГОД 3047
МОДУЛЬ: VPN_CODEX_SCANNER.PY
НАЗНАЧЕНИЕ: Асинхронный сбор, валидация и фильтрация узлов связи древней сети
===============================================================================
"""

import asyncio
import base64
import glob
import json
import os
import re
import socket
import sys
import time
import urllib.parse
import urllib.request
from typing import List, Dict, Optional, Set

# // Обеспечение чистоты вывода в консоль при любых кодировках терминала
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# // Древние свитки зеркал с чертежами узлов связи
DEFAULT_MIRRORS = [
    f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/{i}.txt"
    for i in range(1, 27)
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"


class CodexVpnNode:
    """
    // Структура узла связи, извлеченного из руин цифровой чумы
    """
    def __init__(self, raw_uri: str, protocol: str, host: str, port: int, remark: str = ""):
        self.raw_uri = raw_uri
        self.protocol = protocol
        self.host = host
        self.port = port
        self.remark = remark
        self.latency_ms: Optional[float] = None
        self.is_alive: bool = False
        self.error_reason: str = ""

    def endpoint_key(self) -> str:
        # // Уникальный отпечаток узла (протокол + хост + порт) для отсечения двойников
        return f"{self.protocol}://{self.host}:{self.port}"

    def to_dict(self) -> Dict:
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "remark": self.remark,
            "latency_ms": round(self.latency_ms, 2) if self.latency_ms is not None else None,
            "is_alive": self.is_alive,
            "uri": self.raw_uri
        }


class CodexParser:
    """
    // Расшифровщик древних протоколов передачи сигналов
    """

    @staticmethod
    def decode_base64_safely(data: str) -> str:
        # // Восстановление бинарной нити через выравнивание паддинга
        clean = data.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        padding = len(clean) % 4
        if padding != 0:
            clean += "=" * (4 - padding)
        try:
            return base64.b64decode(clean).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    @classmethod
    def parse_uri(cls, uri: str) -> Optional[CodexVpnNode]:
        uri = uri.strip()
        if not uri or "://" not in uri:
            return None

        protocol = uri.split("://")[0].lower()

        try:
            # // Расшифровка протокола VMess (содержит JSON в Base64)
            if protocol == "vmess":
                b64_part = uri[8:].split("#")[0].split("?")[0]
                decoded_json = cls.decode_base64_safely(b64_part)
                if not decoded_json:
                    return None
                data = json.loads(decoded_json)
                host = str(data.get("add", "")).strip()
                port = int(data.get("port", 0))
                remark = str(data.get("ps", "")).strip()
                if host and port > 0:
                    return CodexVpnNode(uri, "vmess", host, port, remark)

            # // Расшифровка протокола Shadowsocks
            elif protocol in ("ss", "shadowsocks"):
                parsed = urllib.parse.urlparse(uri)
                remark = urllib.parse.unquote(parsed.fragment or "")
                netloc = parsed.netloc
                if "@" in netloc:
                    user_info, host_port = netloc.split("@", 1)
                    host, port_str = host_port.split(":")
                    return CodexVpnNode(uri, "shadowsocks", host, int(port_str), remark)
                else:
                    decoded = cls.decode_base64_safely(netloc)
                    if "@" in decoded:
                        _, host_port = decoded.split("@", 1)
                        host, port_str = host_port.split(":")
                        return CodexVpnNode(uri, "shadowsocks", host, int(port_str), remark)

            # // Универсальная расшифровка VLESS, Trojan, Hysteria, TUIC, Juicity
            elif protocol in ("vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "juicity"):
                parsed = urllib.parse.urlparse(uri)
                host = parsed.hostname
                port = parsed.port
                remark = urllib.parse.unquote(parsed.fragment or "")
                if host and port:
                    return CodexVpnNode(uri, protocol, host, port, remark)

        except Exception:
            return None

        return None

    @classmethod
    def extract_nodes_from_text(cls, text: str) -> List[CodexVpnNode]:
        nodes = []
        # // Проверка: не является ли весь блок монолитным Base64-манускриптом
        if not any(proto in text for proto in ["vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hy2://"]):
            decoded_full = cls.decode_base64_safely(text)
            if any(proto in decoded_full for proto in ["vless://", "vmess://", "trojan://", "ss://", "hysteria://", "hy2://"]):
                text = decoded_full

        lines = [l.strip() for l in text.splitlines() if l.strip()]
        for line in lines:
            node = cls.parse_uri(line)
            if node:
                nodes.append(node)
        return nodes


class CodexHealthChecker:
    """
    // Зонд проверки живости узлов в вакууме эфира
    """
    def __init__(self, timeout: float = 2.0, concurrency: int = 300):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def probe_node(self, node: CodexVpnNode) -> CodexVpnNode:
        # // Нить сокета натянута сквозь века
        async with self.semaphore:
            start_time = time.perf_counter()
            try:
                # // Прямое зондирование TCP-рукопожатия с сервером
                connect_coro = asyncio.open_connection(node.host, node.port)
                reader, writer = await asyncio.wait_for(connect_coro, timeout=self.timeout)
                
                # // Узел ответил на импульс архива
                latency = (time.perf_counter() - start_time) * 1000.0
                node.latency_ms = latency
                node.is_alive = True
                
                # // Застёжка аутентификации скрепляет эпохи — бережно закрываем поток
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except asyncio.TimeoutError:
                node.is_alive = False
                node.error_reason = "Timeout"
            except socket.gaierror:
                node.is_alive = False
                node.error_reason = "DNS Lookup Failed"
            except ConnectionRefusedError:
                node.is_alive = False
                node.error_reason = "Connection Refused"
            except Exception as e:
                node.is_alive = False
                node.error_reason = str(e)

            return node

    async def check_all(self, nodes: List[CodexVpnNode], on_progress=None) -> List[CodexVpnNode]:
        tasks = []
        completed = 0
        total = len(nodes)

        async def _wrapped_probe(n):
            nonlocal completed
            res = await self.probe_node(n)
            completed += 1
            if on_progress and (completed % 50 == 0 or completed == total):
                on_progress(completed, total)
            return res

        for n in nodes:
            tasks.append(asyncio.create_task(_wrapped_probe(n)))

        results = await asyncio.gather(*tasks)
        return list(results)


def fetch_url_sync(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="ignore")


class CodexScannerApp:
    """
    // Главный исполнительный блок архивариуса
    """
    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir

    def load_from_local_directory(self, dir_path: str, files_pattern: str = "*.txt") -> List[CodexVpnNode]:
        all_nodes = []
        seen_endpoints: Set[str] = set()
        file_paths = sorted(glob.glob(os.path.join(dir_path, files_pattern)))

        print(f"[*] Считывание локальных свитков из {dir_path} ({len(file_paths)} файлов)...")
        for idx, fpath in enumerate(file_paths, 1):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                nodes = CodexParser.extract_nodes_from_text(content)
                new_nodes = 0
                for n in nodes:
                    key = n.endpoint_key()
                    if key not in seen_endpoints:
                        seen_endpoints.add(key)
                        all_nodes.append(n)
                        new_nodes += 1
                fname = os.path.basename(fpath)
                print(f"  [{idx:02d}/{len(file_paths):02d}] {fname}: +{new_nodes} уникальных узлов (всего: {len(all_nodes)})")
            except Exception as e:
                print(f"  [!] Ошибка чтения файла {fpath}: {e}")

        return all_nodes

    def fetch_mirrors(self, mirror_urls: List[str]) -> List[CodexVpnNode]:
        all_nodes = []
        seen_endpoints: Set[str] = set()

        print(f"[*] Сканирование {len(mirror_urls)} сетевых зеркал архива...")
        for idx, url in enumerate(mirror_urls, 1):
            try:
                print(f"  [{idx:02d}/{len(mirror_urls):02d}] Загрузка: {url}")
                content = fetch_url_sync(url)
                nodes = CodexParser.extract_nodes_from_text(content)
                new_nodes = 0
                for n in nodes:
                    key = n.endpoint_key()
                    if key not in seen_endpoints:
                        seen_endpoints.add(key)
                        all_nodes.append(n)
                        new_nodes += 1
                print(f"       -> Найдено уникальных узлов: {new_nodes} (всего в пуле: {len(all_nodes)})")
            except Exception as e:
                print(f"       [!] Ошибка считывания зеркала {url}: {e}")

        return all_nodes

    async def run(self, source_path: Optional[str] = None, mirror_ids: Optional[List[int]] = None, 
                  max_servers: int = 100, timeout: float = 2.0, concurrency: int = 300,
                  limit_scan: Optional[int] = None):
        
        raw_nodes: List[CodexVpnNode] = []

        # // 1. Проверяем наличие локального репозитория или указанного пути
        if source_path and os.path.isdir(source_path):
            raw_nodes = self.load_from_local_directory(source_path)
        elif source_path and os.path.isfile(source_path):
            print(f"[*] Считывание одиночного свитка: {source_path}")
            with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
                raw_nodes = CodexParser.extract_nodes_from_text(f.read())
        elif os.path.isdir("configs_repo/githubmirror"):
            print("[*] Обнаружен локальный архив 'configs_repo/githubmirror'!")
            raw_nodes = self.load_from_local_directory("configs_repo/githubmirror")
        else:
            if mirror_ids:
                selected_mirrors = [
                    f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/{i}.txt"
                    for i in mirror_ids if 1 <= i <= 26
                ]
            else:
                selected_mirrors = DEFAULT_MIRRORS
            raw_nodes = self.fetch_mirrors(selected_mirrors)

        print(f"\n[+] Собрано уникальных узлов для проверки: {len(raw_nodes)}")
        if not raw_nodes:
            print("[!] Не удалось извлечь ни одного узла связи.")
            return

        if limit_scan and limit_scan < len(raw_nodes):
            print(f"[*] Ограничение выборки для проверки: первые {limit_scan} узлов")
            raw_nodes = raw_nodes[:limit_scan]

        print(f"[*] Запуск диагностического зонда (таймаут={timeout}с, потоков={concurrency})...")
        checker = CodexHealthChecker(timeout=timeout, concurrency=concurrency)

        def print_progress(current, total):
            pct = (current / total) * 100
            sys.stdout.write(f"\r    Прогресс зондирования: [{current}/{total}] ({pct:.1f}%)")
            sys.stdout.flush()

        verified_nodes = await checker.check_all(raw_nodes, on_progress=print_progress)
        print("\n")

        # // Фильтрация живых узлов и сортировка по пингу
        alive_nodes = [n for n in verified_nodes if n.is_alive]
        alive_nodes.sort(key=lambda x: x.latency_ms if x.latency_ms is not None else 99999)

        print(f"[+] Проверку выдержали: {len(alive_nodes)} из {len(raw_nodes)} узлов!")

        if max_servers > 0:
            alive_nodes = alive_nodes[:max_servers]

        # // Сохранение артефактов
        self.save_artifacts(alive_nodes)

    def save_artifacts(self, alive_nodes: List[CodexVpnNode]):
        # // 1. Текстовый список для прямого импорта (v2rayNG, Throne, V2Box, Hiddify)
        txt_path = os.path.join(self.output_dir, "working_configs.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            for n in alive_nodes:
                f.write(n.raw_uri + "\n")

        # // 2. Подписка в формате Base64
        b64_path = os.path.join(self.output_dir, "working_configs_base64.txt")
        raw_combined = "\n".join(n.raw_uri for n in alive_nodes)
        encoded_b64 = base64.b64encode(raw_combined.encode("utf-8")).decode("utf-8")
        with open(b64_path, "w", encoding="utf-8") as f:
            f.write(encoded_b64)

        # // 3. Детализированный отчет в формате JSON
        json_path = os.path.join(self.output_dir, "working_configs.json")
        report = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "total_alive": len(alive_nodes),
            "servers": [n.to_dict() for n in alive_nodes]
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("=" * 60)
        print("СОХРАНЕНЫ АРТЕФАКТЫ КОДЕКСА:")
        print(f"  -> Прямой список URI:      {os.path.abspath(txt_path)}")
        print(f"  -> Подписка Base64:        {os.path.abspath(b64_path)}")
        print(f"  -> Аналитический JSON:     {os.path.abspath(json_path)}")
        print("=" * 60)

        if alive_nodes:
            print("\nТОП-5 САМЫХ БЫСТРЫХ УЗЛОВ СВЯЗИ:")
            for i, n in enumerate(alive_nodes[:5], 1):
                clean_remark = re.sub(r'[^\w\s\-\.\(\)]', '', n.remark)[:30]
                print(f"  {i}. [{n.protocol.upper()}] {n.host}:{n.port} - {n.latency_ms:.1f} ms ({clean_remark})")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="VPN Codex Scanner - Health check & aggregator")
    parser.add_argument("--source", type=str, default=None, help="Путь к файлу или папке с зеркалами (например 'configs_repo/githubmirror')")
    parser.add_argument("--mirrors", type=str, default="1-3", help="Диапазон зеркал при скачивании из сети (например: '1-5' или 'all')")
    parser.add_argument("--max", type=int, default=100, help="Максимальное число лучших серверов в результате (по умолчанию 100)")
    parser.add_argument("--limit-scan", type=int, default=None, help="Ограничить количество проверяемых серверов")
    parser.add_argument("--timeout", type=float, default=1.8, help="Таймаут проверки сокета в секундах (по умолчанию 1.8)")
    parser.add_argument("--concurrency", type=int, default=400, help="Число параллельных потоков проверки (по умолчанию 400)")
    parser.add_argument("--outdir", type=str, default=".", help="Директория для сохранения результатов")

    args = parser.parse_args()

    mirror_ids = []
    if args.mirrors.lower() == "all":
        mirror_ids = list(range(1, 27))
    elif "-" in args.mirrors:
        start, end = map(int, args.mirrors.split("-"))
        mirror_ids = list(range(start, end + 1))
    else:
        mirror_ids = [int(x.strip()) for x in args.mirrors.split(",") if x.strip().isdigit()]

    app = CodexScannerApp(output_dir=args.outdir)
    asyncio.run(app.run(
        source_path=args.source,
        mirror_ids=mirror_ids,
        max_servers=args.max,
        timeout=args.timeout,
        concurrency=args.concurrency,
        limit_scan=args.limit_scan
    ))


if __name__ == "__main__":
    main()
