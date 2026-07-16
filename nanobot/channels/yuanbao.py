"""
Yuanbao (Tencent Yuanbao Bot) channel implementation for nanobot.

Connects to the Yuanbao WebSocket gateway, handles authentication (AUTH_BIND),
heartbeat, reconnection, message receive and send via protobuf protocol.

Configuration (in ~/.nanobot/config.json):
    "channels": {
        "yuanbao": {
            "enabled": true,
            "appId": "...",
            "appSecret": "...",
            "botId": "...",
            "wsUrl": "wss://bot-wss.yuanbao.tencent.com/wss/connection",
            "apiDomain": "https://bot.yuanbao.tencent.com",
            "allowFrom": ["*"]
        }
    }
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from loguru import logger as _base_logger
from pydantic import Field
from websockets.asyncio.client import ClientConnection
from websockets.asyncio.client import connect as ws_connect
from websockets.exceptions import ConnectionClosed as WsConnectionClosed

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels._yuanbao_media import (
    build_file_msg_body,
    build_image_msg_body,
    download_url,
    get_cos_credentials,
    guess_mime_type,
    md5_hex,
    upload_to_cos,
)
from nanobot.channels._yuanbao_proto import (
    CMD_TYPE,
    HERMES_INSTANCE_ID,
    _fields_to_dict,
    _get_string,
    _get_varint,
    _parse_fields,
    decode_conn_msg,
    decode_inbound_push,
    decode_send_c2c_rsp,
    encode_auth_bind,
    encode_ping,
    encode_push_ack,
    encode_send_c2c_message,
    encode_send_group_message,
    next_seq_no,
)
from nanobot.channels._yuanbao_sticker import (
    build_sticker_msg_body,
    get_random_sticker,
    get_sticker_by_name,
)
from nanobot.channels.base import BaseChannel
from nanobot.config.paths import get_media_dir
from nanobot.config.schema import Base
from nanobot.security.network import validate_url_target
from nanobot.utils.helpers import safe_filename

logger = _base_logger.bind(channel="yuanbao")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WS_GATEWAY_URL = "wss://bot-wss.yuanbao.tencent.com/wss/connection"
DEFAULT_API_DOMAIN = "https://bot.yuanbao.tencent.com"

HEARTBEAT_INTERVAL_SECONDS = 30.0
CONNECT_TIMEOUT_SECONDS = 15.0
AUTH_TIMEOUT_SECONDS = 10.0
MAX_RECONNECT_ATTEMPTS = 100
DEFAULT_SEND_TIMEOUT = 30.0
WS_CLOSE_TIMEOUT_S = 1.0

NO_RECONNECT_CLOSE_CODES = {4012, 4013, 4014, 4018, 4019, 4021}
HEARTBEAT_TIMEOUT_THRESHOLD = 2
AUTH_FAILED_CODES = {4001, 4002, 4003}
AUTH_RETRYABLE_CODES = {4010, 4011, 4099}

_DOWNLOAD_TIMEOUT = httpx.Timeout(60.0)
_CONNECT_TIMEOUT = httpx.Timeout(CONNECT_TIMEOUT_SECONDS)
_MAX_TEXT_CHUNK = 4000

# Map TIM element type names to numeric IDs
_MSG_TYPE_NAME_TO_ID = {
    "TIMTextElem": 1,
    "TIMImageElem": 2,
    "TIMSoundElem": 3,
    "TIMCustomElem": 4,
    "TIMFileElem": 5,
    "TIMFaceElem": 6,
    "TIMVideoFileElem": 7,
}


def _normalize_msg_type(mt: str | int) -> int:
    """Normalise msg_type to an integer id. Accepts both string and int."""
    if isinstance(mt, int):
        return mt
    if isinstance(mt, str) and mt:
        return _MSG_TYPE_NAME_TO_ID.get(mt, 0)
    return 0


# Regex for detecting sticker request in message content: [sticker:name] or [表情:name]
_STICKER_RE = re.compile(r"^\[(?:sticker|表情):([^\]]+)\]$")

# ---------------------------------------------------------------------------
# Version / platform constants
# ---------------------------------------------------------------------------

_APP_VERSION = "1.0.0"
_BOT_VERSION = "1.0.0"
_YUANBAO_INSTANCE_ID = str(HERMES_INSTANCE_ID)
_OPERATION_SYSTEM = sys.platform


def _compute_signature(nonce: str, timestamp: str, app_key: str, app_secret: str) -> str:
    """Compute HMAC-SHA256 signature for sign-token API."""
    plain = nonce + timestamp + app_key + app_secret
    return hmac.new(app_secret.encode(), plain.encode(), hashlib.sha256).hexdigest()


def _build_timestamp() -> str:
    """Build Beijing-time ISO-8601 timestamp (no milliseconds)."""
    bjtime = datetime.now(tz=timezone(timedelta(hours=8)))
    return bjtime.strftime("%Y-%m-%dT%H:%M:%S+08:00")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


class YuanbaoConfig(Base):
    """Yuanbao channel configuration."""

    enabled: bool = False
    app_id: str = ""
    app_secret: str = ""
    bot_id: str = ""
    ws_url: str = DEFAULT_WS_GATEWAY_URL
    api_domain: str = DEFAULT_API_DOMAIN
    route_env: str = ""
    allow_from: list[str] = Field(default_factory=list)
    streaming: bool = False
    media_resolve_concurrency: int = Field(default=6, ge=1, le=12)


# ---------------------------------------------------------------------------
# Token cache (class-level shared state)
# ---------------------------------------------------------------------------

_token_cache: dict[str, dict[str, Any]] = {}
_token_locks: dict[str, asyncio.Lock] = {}
_CACHE_REFRESH_MARGIN_S = 60
_TOKEN_RETRYABLE_CODE = 10099
_TOKEN_MAX_RETRIES = 3
_TOKEN_RETRY_DELAY_S = 1.0
_TOKEN_HTTP_TIMEOUT_S = 10.0
_TOKEN_PATH = "/api/v5/robotLogic/sign-token"
_DOWNLOAD_INFO_PATH = "/api/resource/v1/download"


async def _get_sign_token(config: YuanbaoConfig) -> dict[str, Any]:
    """Get WS auth token with cache.

    Returns dict with keys: token, bot_id, duration, product, source, expire_ts.
    """
    app_key = config.app_id
    app_secret = config.app_secret
    api_domain = config.api_domain
    route_env = config.route_env

    # Check cache
    cached = _token_cache.get(app_key)
    if cached and cached["expire_ts"] - time.time() > _CACHE_REFRESH_MARGIN_S:
        remain = int(cached["expire_ts"] - time.time())
        logger.info("Using cached token ({})s remaining)", remain)
        return dict(cached)

    # Refresh with lock
    if app_key not in _token_locks:
        _token_locks[app_key] = asyncio.Lock()

    async with _token_locks[app_key]:
        cached = _token_cache.get(app_key)
        if cached and cached["expire_ts"] - time.time() > _CACHE_REFRESH_MARGIN_S:
            return dict(cached)

        # Fetch token
        url = f"{api_domain.rstrip('/')}{_TOKEN_PATH}"
        async with httpx.AsyncClient(timeout=_TOKEN_HTTP_TIMEOUT_S) as client:
            for attempt in range(_TOKEN_MAX_RETRIES + 1):
                nonce = secrets.token_hex(16)
                timestamp = _build_timestamp()
                signature = _compute_signature(nonce, timestamp, app_key, app_secret)

                payload = {
                    "app_key": app_key,
                    "nonce": nonce,
                    "signature": signature,
                    "timestamp": timestamp,
                }
                headers = {
                    "Content-Type": "application/json",
                    "X-AppVersion": _APP_VERSION,
                    "X-OperationSystem": _OPERATION_SYSTEM,
                    "X-Instance-Id": _YUANBAO_INSTANCE_ID,
                    "X-Bot-Version": _BOT_VERSION,
                }
                if route_env:
                    headers["X-Route-Env"] = route_env

                response = await client.post(url, json=payload, headers=headers)
                if response.status_code != 200:
                    raise RuntimeError(f"Sign token API returned {response.status_code}: {response.text[:200]}")

                result_data = response.json()
                code = result_data.get("code")
                if code == 0:
                    data = result_data.get("data")
                    if not isinstance(data, dict):
                        raise ValueError(f"Sign token response missing 'data' field: {result_data}")
                    duration = data.get("duration", 3600)
                    expire_ts = time.time() + duration
                    _token_cache[app_key] = {
                        "token": data.get("token", ""),
                        "bot_id": data.get("bot_id", ""),
                        "duration": duration,
                        "product": data.get("product", ""),
                        "source": data.get("source", ""),
                        "expire_ts": expire_ts,
                    }
                    logger.info("Sign token success: bot_id={}", data.get("bot_id"))
                    return dict(_token_cache[app_key])

                if code == _TOKEN_RETRYABLE_CODE and attempt < _TOKEN_MAX_RETRIES:
                    logger.warning(
                        "Sign token retryable: code={}, retrying in {}s (attempt={}/{})",
                        code, _TOKEN_RETRY_DELAY_S, attempt + 1, _TOKEN_MAX_RETRIES,
                    )
                    await asyncio.sleep(_TOKEN_RETRY_DELAY_S)
                    continue

                msg = result_data.get("msg", "")
                raise RuntimeError(f"Sign token error: code={code}, msg={msg}")

        raise RuntimeError("Sign token failed: max retries exceeded")


async def _resolve_download_url(url: str, config: YuanbaoConfig) -> str:
    """Resolve a Yuanbao resource download URL to a real COS download URL.

    If *url* points to ``/api/resource/download?resourceId=…`` (a temporary
    resource link that requires auth), this exchanges the ``resourceId`` for a
    real COS download URL via the Yuanbao API.  Other URLs are returned as-is.

    Reference: OpenClaw JS ``resolveFetchUrl()`` in ``media.js``.
    """
    try:
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        if parsed.path == "/api/resource/download":
            qs = parse_qs(parsed.query)
            resource_id = qs.get("resourceId", [None])[0]
            if not resource_id:
                return url

            token_data = await _get_sign_token(config)
            api_domain = config.api_domain.rstrip("/")
            api_url = f"{api_domain}{_DOWNLOAD_INFO_PATH}?resourceId={resource_id}"

            headers = {
                "X-ID": token_data.get("bot_id", ""),
                "X-Token": token_data.get("token", ""),
                "X-Source": token_data.get("source", "bot"),
                "X-AppVersion": _APP_VERSION,
                "X-OperationSystem": _OPERATION_SYSTEM,
                "X-Instance-Id": _YUANBAO_INSTANCE_ID,
                "X-Bot-Version": _BOT_VERSION,
            }
            if config.route_env:
                headers["X-Route-Env"] = config.route_env

            async with httpx.AsyncClient(timeout=_TOKEN_HTTP_TIMEOUT_S) as client:
                resp = await client.get(api_url, headers=headers)
                if resp.status_code != 200:
                    logger.warning("yuanbao: download info API returned {}: {}", resp.status_code, resp.text[:200])
                    return url
                data = resp.json()
                real_url = data.get("url") or data.get("realUrl") or data.get("data", {}).get("url")
                if real_url:
                    logger.debug("yuanbao: resolved download URL: resourceId={}", resource_id)
                    return real_url
                logger.warning("yuanbao: download info API returned no URL: data={}", str(data)[:200])
    except Exception as e:
        logger.warning("yuanbao: failed to resolve download URL: {}", e)
    return url


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------


class YuanbaoChannel(BaseChannel):
    """Yuanbao (Tencent Yuanbao Bot) channel.

    Connects to the Yuanbao WebSocket gateway using a persistent connection.
    Supports both direct messages (C2C) and group chats.
    """

    name = "yuanbao"
    display_name = "Yuanbao"

    def __init__(self, config: Any, bus: MessageBus):
        if isinstance(config, dict):
            config = YuanbaoConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: YuanbaoConfig = config

        # WebSocket connection
        self._ws: ClientConnection | None = None
        self._connect_id: str | None = None
        self._bot_id: str = config.bot_id or ""

        # HTTP client
        self._http: httpx.AsyncClient | None = None

        # Media storage
        self._media_root: Path = get_media_dir("yuanbao")

        # Background tasks
        self._heartbeat_task: asyncio.Task | None = None
        self._recv_task: asyncio.Task | None = None
        self._background_tasks: set[asyncio.Task] = set()

        # Pending RPC responses
        self._pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self._pending_pong: asyncio.Future | None = None
        self._consecutive_hb_timeouts: int = 0

        # Inbound message deduplication
        self._processed_ids: deque[str] = deque(maxlen=2000)

        # Track recently sent message texts to skip delivery callbacks
        # (the server echoes every sent message back as a C2C.CallbackAfterSendMsg)
        self._sent_msg_bodies: deque[str] = deque(maxlen=200)

        # Reconnect state
        self._reconnect_attempts: int = 0
        self._reconnecting: bool = False
        self._close_code: int = 0

        # Chat lock for serialised sends per chat
        self._chat_locks: dict[str, asyncio.Lock] = {}

        # Inbound debounce buffer
        self._inbound_buffer: dict[str, list[bytes]] = {}
        self._inbound_timers: dict[str, asyncio.TimerHandle] = {}
        self._debounce_window: float = 1.5

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return YuanbaoConfig().model_dump(by_alias=True)

    async def start(self) -> None:
        if not self.config.app_id or not self.config.app_secret:
            logger.error("yuanbao: appId and appSecret must be configured")
            return

        self._running = True
        self._http = httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT)

        while self._running:
            try:
                await self._connect()
                self._reconnect_attempts = 0
                self._reconnecting = False

                # Block until the current connection drops (background tasks exit)
                await self._await_disconnect()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("yuanbao: connection error: {}", e)

            if not self._running:
                break

            # If close code is terminal (auth/conflict errors), don't reconnect
            if self._close_code in NO_RECONNECT_CLOSE_CODES:
                logger.error(
                    "yuanbao: terminal close code {} (in NO_RECONNECT_CLOSE_CODES), "
                    "stopping reconnection",
                    self._close_code,
                )
                break

            wait = min(2 ** self._reconnect_attempts, 60) if self._reconnect_attempts > 0 else 5
            self._reconnect_attempts += 1
            if self._reconnect_attempts > MAX_RECONNECT_ATTEMPTS:
                logger.error("yuanbao: max reconnect attempts ({}) exceeded", MAX_RECONNECT_ATTEMPTS)
                break
            logger.info("yuanbao: reconnecting in {}s (attempt {}/{})", wait, self._reconnect_attempts, MAX_RECONNECT_ATTEMPTS)
            await asyncio.sleep(wait)

    async def stop(self) -> None:
        self._running = False
        self._cancel_background_tasks()

        # Cancel heartbeat
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
            self._heartbeat_task = None

        # Cancel recv
        if self._recv_task:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
            self._recv_task = None

        # Fail pending futures
        disc_err = RuntimeError("yuanbao: disconnected")
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(disc_err)
        self._pending.clear()

        # Close WS
        await self._cleanup_ws()

        # Close HTTP
        if self._http:
            try:
                await self._http.aclose()
            except Exception:
                pass
            self._http = None

        # Cancel inbound buffers
        for timer in self._inbound_timers.values():
            timer.cancel()
        self._inbound_timers.clear()
        self._inbound_buffer.clear()

        logger.info("yuanbao: stopped")

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def _connect(self) -> None:
        """Connect to Yuanbao WS gateway and authenticate."""
        # Cancel background loops from any previous connection
        await self._cancel_background_loops()

        # Close any remaining WS from previous connection
        await self._cleanup_ws()

        # Reset close code
        self._close_code = 0

        logger.info("yuanbao: fetching sign token from {}", self.config.api_domain)
        token_data = await _get_sign_token(self.config)

        if token_data.get("bot_id"):
            self._bot_id = str(token_data["bot_id"])

        ws_url = self.config.ws_url or DEFAULT_WS_GATEWAY_URL
        logger.info("yuanbao: connecting to {}", ws_url)

        self._ws = await asyncio.wait_for(
            ws_connect(ws_url, ping_interval=None, ping_timeout=None, close_timeout=5),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )

        authed = await self._authenticate(token_data)
        if not authed:
            await self._cleanup_ws()
            raise RuntimeError("yuanbao: authentication failed")

        self._reconnect_attempts = 0

        # Start background loops
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(), name="yuanbao-heartbeat"
        )
        self._recv_task = asyncio.create_task(
            self._receive_loop(), name="yuanbao-recv"
        )

        logger.info("yuanbao: connected (bot_id={})", self._bot_id)

    async def _authenticate(self, token_data: dict) -> bool:
        """Send AUTH_BIND and wait for BIND_ACK."""
        if self._ws is None:
            return False

        token = token_data.get("token", "")
        uid = self._bot_id or token_data.get("bot_id", "")
        source = token_data.get("source") or "bot"
        route_env = self.config.route_env or token_data.get("route_env", "") or ""

        msg_id = str(uuid.uuid4())
        auth_bytes = encode_auth_bind(
            biz_id="ybBot",
            uid=uid,
            source=source,
            token=token,
            msg_id=msg_id,
            app_version=_APP_VERSION,
            operation_system=_OPERATION_SYSTEM,
            bot_version=_BOT_VERSION,
            route_env=route_env,
        )
        await self._ws.send(auth_bytes)
        logger.debug("yuanbao: AUTH_BIND sent (msg_id={} uid={})", msg_id, uid)

        try:
            deadline = asyncio.get_running_loop().time() + AUTH_TIMEOUT_SECONDS
            while True:
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    logger.error("yuanbao: AUTH_BIND timeout")
                    return False

                raw = await asyncio.wait_for(self._ws.recv(), timeout=remaining)
                if not isinstance(raw, (bytes, bytearray)):
                    continue

                try:
                    msg = decode_conn_msg(bytes(raw))
                except Exception:
                    continue

                head = msg.get("head", {})
                cmd_type = head.get("cmd_type", -1)
                cmd = head.get("cmd", "")

                if cmd_type == CMD_TYPE["Response"] and cmd == "auth-bind":
                    connect_id = self._extract_connect_id(msg)
                    if connect_id:
                        self._connect_id = connect_id
                        logger.info("yuanbao: BIND_ACK received (connectId={})", connect_id)
                        return True
                    else:
                        logger.error("yuanbao: BIND_ACK missing connectId")
                        return False
        except asyncio.TimeoutError:
            logger.error("yuanbao: AUTH_BIND timeout")
            return False
        except Exception as exc:
            logger.error("yuanbao: AUTH_BIND error: {}", exc)
            return False

    @staticmethod
    def _extract_connect_id(decoded_msg: dict) -> str | None:
        """Extract connectId from decoded BIND_ACK message."""
        data: bytes | None = decoded_msg.get("data")
        if not data:
            return None
        try:
            fdict = _fields_to_dict(_parse_fields(data))
            code = _get_varint(fdict, 1)
            if code != 0:
                message = _get_string(fdict, 2)
                logger.error("yuanbao: AuthBindRsp error: code={} message={}", code, message)
                return None
            connect_id = _get_string(fdict, 3)
            return connect_id if connect_id else None
        except Exception as exc:
            logger.warning("yuanbao: Failed to extract connectId: {}", exc)
            return None

    async def _cleanup_ws(self) -> None:
        """Close and clear the WebSocket connection."""
        ws = self._ws
        self._ws = None
        if ws is not None:
            try:
                await asyncio.wait_for(ws.close(), timeout=WS_CLOSE_TIMEOUT_S)
            except asyncio.TimeoutError:
                logger.debug("yuanbao: WS close handshake exceeded {}s — dropping", WS_CLOSE_TIMEOUT_S)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Send ping every 30s; trigger reconnect after threshold misses."""
        try:
            while self._running:
                await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
                if self._ws is None:
                    continue
                try:
                    msg_id = str(uuid.uuid4())
                    ping_bytes = encode_ping(msg_id)
                    loop = asyncio.get_running_loop()
                    pong_future: asyncio.Future = loop.create_future()
                    self._pending_pong = pong_future
                    self._pending[msg_id] = pong_future
                    await self._ws.send(ping_bytes)
                    logger.debug("yuanbao: PING sent (msg_id={})", msg_id)
                    try:
                        await asyncio.wait_for(pong_future, timeout=10.0)
                        self._consecutive_hb_timeouts = 0
                    except asyncio.TimeoutError:
                        self._pending.pop(msg_id, None)
                        self._consecutive_hb_timeouts += 1
                        logger.warning(
                            "yuanbao: PONG timeout ({}/{})",
                            self._consecutive_hb_timeouts,
                            HEARTBEAT_TIMEOUT_THRESHOLD,
                        )
                        if self._consecutive_hb_timeouts >= HEARTBEAT_TIMEOUT_THRESHOLD:
                            logger.warning("yuanbao: heartbeat threshold exceeded, reconnecting")
                            self._schedule_reconnect()
                            return
                    finally:
                        self._pending.pop(msg_id, None)
                        self._pending_pong = None
                except Exception as exc:
                    logger.debug("yuanbao: heartbeat send failed: {}", exc)
        except asyncio.CancelledError:
            pass

    # ------------------------------------------------------------------
    # Receive loop
    # ------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        """Read WS frames and dispatch by cmd_type."""
        try:
            async for raw in self._ws:
                if not isinstance(raw, (bytes, bytearray)):
                    continue
                await self._handle_frame(bytes(raw))
        except asyncio.CancelledError:
            pass
        except WsConnectionClosed as e:
            self._close_code = e.code
            logger.warning("yuanbao: receive loop exited: {} (code={})", e, e.code)
            self._schedule_reconnect()
        except Exception as e:
            logger.warning("yuanbao: receive loop exited: {}", e)
            self._schedule_reconnect()

    async def _handle_frame(self, raw: bytes) -> None:
        """Handle a single WebSocket frame."""
        try:
            msg = decode_conn_msg(raw)
        except Exception as exc:
            logger.debug("yuanbao: failed to decode frame: {}", exc)
            return

        head = msg.get("head", {})
        cmd_type = head.get("cmd_type", -1)
        cmd = head.get("cmd", "")
        msg_id = head.get("msg_id", "")
        need_ack = head.get("need_ack", False)
        data: bytes = msg.get("data", b"")

        # HEARTBEAT_ACK
        if cmd_type == CMD_TYPE["Response"] and cmd == "ping":
            logger.debug("yuanbao: HEARTBEAT_ACK (msg_id={})", msg_id)
            if self._pending_pong is not None and not self._pending_pong.done():
                self._pending_pong.set_result(True)
            elif msg_id and msg_id in self._pending:
                fut = self._pending.pop(msg_id)
                if not fut.done():
                    fut.set_result(True)
            return

        # Fire-and-forget heartbeat ACKs
        if cmd_type == CMD_TYPE["Response"] and cmd in {
            "send_group_heartbeat",
            "send_private_heartbeat",
        }:
            logger.debug("yuanbao: Heartbeat ACK: cmd={} msg_id={}", cmd, msg_id)
            return

        # Response to an outbound RPC call
        if cmd_type == CMD_TYPE["Response"]:
            if msg_id and msg_id in self._pending:
                fut = self._pending.pop(msg_id)
                if not fut.done():
                    result = {"head": head}
                    if data:
                        result["data"] = data
                    fut.set_result(result)
            else:
                data_preview = " ".join(f"{b:02x}" for b in data[:32]) if data else "(empty)"
                # Try to decode business-level response for known commands
                if data and cmd in ("send_c2c_message",):
                    biz_rsp = decode_send_c2c_rsp(data)
                    logger.info(
                        "yuanbao: RPC response: cmd={} msg_id={} status={} biz_result={} err_msg={!r} "
                        "data={}",
                        cmd, msg_id, head.get("status", 0),
                        biz_rsp["result"], biz_rsp["err_msg"], data_preview,
                    )
                else:
                    logger.info(
                        "yuanbao: RPC response: cmd={} msg_id={} status={} data={}",
                        cmd, msg_id, head.get("status", 0), data_preview,
                    )
            return

        # Server-initiated Push (inbound message)
        if cmd_type == CMD_TYPE["Push"]:
            logger.debug("yuanbao: Push received: cmd={} msg_id={} data_len={}", cmd, msg_id, len(data))
            if need_ack and self._ws is not None:
                try:
                    ack_bytes = encode_push_ack(head)
                    await self._ws.send(ack_bytes)
                except Exception as ack_exc:
                    logger.debug("yuanbao: Failed to send PushAck: {}", ack_exc)

            if not data:
                return

            # Genuine inbound message
            logger.debug("yuanbao: inbound push data_len={}", len(data))
            self._push_to_inbound(data)
            return

        logger.debug("yuanbao: ignoring frame: cmd_type={} cmd={} msg_id={}", cmd_type, cmd, msg_id)

    # ------------------------------------------------------------------
    # Inbound dispatch
    # ------------------------------------------------------------------

    def _push_to_inbound(self, raw_data: bytes) -> None:
        """Debounced inbound dispatch - aggregate multi-part messages."""
        # Extract sender key for debounce grouping
        key = self._extract_sender_key(raw_data)

        # Reset debounce timer for this key
        existing_timer = self._inbound_timers.pop(key, None)
        if existing_timer:
            existing_timer.cancel()

        if key not in self._inbound_buffer:
            self._inbound_buffer[key] = []
        self._inbound_buffer[key].append(raw_data)

        logger.debug("yuanbao: debounce: buffered for key={} count={}", key, len(self._inbound_buffer[key]))

        loop = asyncio.get_running_loop()
        timer = loop.call_later(self._debounce_window, self._flush_inbound_buffer, key)
        self._inbound_timers[key] = timer

    def _extract_sender_key(self, raw_data: bytes) -> str:
        """Extract sender key for debounce grouping (from_account:group_code)."""
        # Try JSON first (callback pushes from the platform)
        try:
            parsed = json.loads(raw_data.decode("utf-8"))
            if isinstance(parsed, dict):
                from_account = parsed.get("from_account", "") or parsed.get("From_Account", "")
                group_code = parsed.get("group_code", "") or parsed.get("group_id", "") or parsed.get("GroupId", "")
                if from_account:
                    return f"{from_account}:{group_code}"
        except Exception:
            pass
        # Protobuf path
        try:
            push = decode_inbound_push(raw_data)
            if push:
                return f"{push.get('from_account', '')}:{push.get('group_code', '')}"
        except Exception:
            pass
        return f"__unknown_{id(raw_data)}"

    def _flush_inbound_buffer(self, key: str) -> None:
        """Flush debounce buffer and execute inbound message processing."""
        self._inbound_timers.pop(key, None)
        data_list = self._inbound_buffer.pop(key, [])
        if not data_list:
            return

        logger.debug("yuanbao: debounce flush: key={} aggregated {} frames", key, len(data_list))
        task = asyncio.create_task(self._process_inbound(data_list))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _process_inbound(self, data_list: list[bytes]) -> None:
        """Process aggregated inbound message data."""
        # For simplicity, process the first frame's data (multi-frame aggregation
        # can be extended later). Most messages arrive as a single frame.
        raw_data = data_list[0]

        # Try protobuf first, then JSON fallback
        push = decode_inbound_push(raw_data)
        if push is None:
            # JSON fallback — the push data may be JSON instead of protobuf
            try:
                parsed = json.loads(raw_data.decode("utf-8"))
                if isinstance(parsed, dict):
                    # Map JSON fields (both camelCase and snake_case variants)
                    msg_body_raw = parsed.get("msg_body") or parsed.get("MsgBody") or []
                    msg_body = []
                    for el in msg_body_raw:
                        if isinstance(el, dict):
                            # Convert string msg_type (e.g. "TIMTextElem") to int
                            raw_mt = el.get("msg_type") or el.get("MsgType") or 0
                            if isinstance(raw_mt, str):
                                _msg_type_map = {
                                    "TIMTextElem": 1, "TIMImageElem": 2,
                                    "TIMSoundElem": 3, "TIMCustomElem": 4,
                                    "TIMFileElem": 5, "TIMFaceElem": 6,
                                    "TIMVideoFileElem": 7,
                                }
                                mt = _msg_type_map.get(raw_mt, 1)
                            else:
                                mt = int(raw_mt) if raw_mt else 0
                            mc = el.get("msg_content") or el.get("MsgContent") or {}
                            msg_body.append({"msg_type": mt, "msg_content": mc})

                    from_account = (
                        parsed.get("from_account")
                        or parsed.get("From_Account")
                        or ""
                    )
                    group_code = (
                        parsed.get("group_code")
                        or parsed.get("group_id")
                        or parsed.get("GroupId")
                        or parsed.get("GroupCode")
                        or ""
                    )

                    push = {
                        "callback_command": parsed.get("callback_command") or parsed.get("CallbackCommand") or "",
                        "from_account": from_account,
                        "to_account": parsed.get("to_account") or parsed.get("To_Account") or "",
                        "sender_nickname": parsed.get("sender_nickname") or parsed.get("SenderNickname") or parsed.get("SenderProfile") or "",
                        "group_id": parsed.get("group_id") or parsed.get("GroupId") or "",
                        "group_code": group_code,
                        "group_name": parsed.get("group_name") or parsed.get("GroupName") or "",
                        "msg_seq": parsed.get("msg_seq") or parsed.get("MsgSeq") or 0,
                        "msg_random": parsed.get("msg_random") or parsed.get("MsgRandom") or 0,
                        "msg_time": parsed.get("msg_time") or parsed.get("MsgTime") or 0,
                        "msg_key": parsed.get("msg_key") or parsed.get("MsgKey") or "",
                        "msg_id": parsed.get("msg_id") or parsed.get("MsgId") or "",
                        "msg_body": msg_body,
                        "cloud_custom_data": parsed.get("cloud_custom_data") or parsed.get("CloudCustomData") or "",
                    }
                    logger.debug(
                        "yuanbao: JSON push parsed: cmd={!r} from={} body_len={}",
                        push["callback_command"], from_account, len(msg_body),
                    )
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as e:
                logger.debug(
                    "yuanbao: JSON decode failed: {} — first 64 bytes: {}",
                    e, " ".join(f"{b:02x}" for b in raw_data[:32]),
                )
                return
        else:
            logger.debug(
                "yuanbao: protobuf decode OK: cmd={!r} from={} body_len={}",
                push.get("callback_command", ""), push.get("from_account", ""),
                len(push.get("msg_body", [])),
            )

        from_account = push.get("from_account", "")
        group_code = push.get("group_code", "")
        group_name = push.get("group_name", "")
        msg_body = push.get("msg_body", [])
        msg_id = push.get("msg_id", "")
        sender_nickname = push.get("sender_nickname", "")

        if not from_account:
            logger.debug("yuanbao: skip — empty from_account")
            return
        if from_account == self._bot_id:
            logger.debug("yuanbao: skip — own message (from_account==bot_id)")
            return

        # Skip delivery callbacks — the server echoes every sent message back
        # as a C2C.CallbackAfterSendMsg.  If the plain text matches something
        # we just sent, ignore it.
        sent_check = " ".join(
            el.get("msg_content", {}).get("text", "")
            for el in msg_body
            if _normalize_msg_type(el.get("msg_type", 0)) == 1
        ).strip()
        if sent_check and sent_check in self._sent_msg_bodies:
            logger.debug("yuanbao: skip — matches recently sent text: {!r}", sent_check[:60])
            return

        # Deduplication
        if msg_id and msg_id in self._processed_ids:
            return
        if msg_id:
            self._processed_ids.append(msg_id)

        # Extract text and media references
        text_parts: list[str] = []
        media_refs: list[dict] = []
        for el in msg_body:
            msg_type = el.get("msg_type")
            content = el.get("msg_content", {})
            # Normalise: protobuf decode returns string, JSON fallback returns int
            mt = _normalize_msg_type(msg_type)
            if mt == 1:  # TIMTextElem
                if text := content.get("text", ""):
                    text_parts.append(text)
            elif mt == 2:  # TIMImageElem
                if url := content.get("url", ""):
                    media_refs.append({"type": "image", "url": url, "uuid": content.get("uuid", "")})
                elif _uuid := content.get("uuid", ""):
                    media_refs.append({"type": "image", "uuid": _uuid})
            elif mt == 5:  # TIMFileElem
                if url := content.get("url", ""):
                    media_refs.append({"type": "file", "url": url, "name": content.get("file_name", "")})
            elif mt == 3:  # TIMSoundElem
                if url := content.get("url", ""):
                    media_refs.append({"type": "audio", "url": url})
            elif mt == 6:  # TIMFaceElem (sticker)
                data_str = content.get("data", "")
                if data_str:
                    try:
                        sticker_data = json.loads(data_str) if isinstance(data_str, str) else data_str
                        sticker_name = sticker_data.get("name", "")
                        if sticker_name:
                            text_parts.append(f"[表情:{sticker_name}]")
                    except (json.JSONDecodeError, TypeError):
                        pass

        text = " ".join(text_parts).strip()
        if not text and not media_refs:
            return

        logger.info(
            "yuanbao: inbound msg from={} chat={} text={!r} media={}",
            from_account,
            "group:" + group_code if group_code else "direct:" + from_account,
            text[:100] if text else "",
            len(media_refs),
        )

        # Determine chat type
        if group_code:
            chat_id = f"group:{group_code}"
            is_dm = False
            content = f"{sender_nickname or from_account}: {text}" if text else ""
        else:
            chat_id = f"direct:{from_account}"
            is_dm = True
            content = text

        # Download media references
        media_paths: list[str] = []
        for ref in media_refs:
            if url := ref.get("url"):
                logger.debug("yuanbao: downloading media: type={} url={} name={!r}", ref.get("type"), url[:80], ref.get("name", ""))
                if local := await self._download_media(url, ref.get("type", "image"), ref.get("name", "")):
                    media_paths.append(local)
                    logger.debug("yuanbao: media downloaded to {}", local)
                else:
                    logger.debug("yuanbao: media download returned None for {}", url[:80])
            elif ref.get("type") == "image" and ref.get("uuid"):
                logger.debug("yuanbao: media has uuid only, skipping download")

        if not content and not media_paths:
            return

        logger.debug("yuanbao: dispatching to _handle_message: content={!r} media_paths={}", content[:80] if content else "", media_paths)

        await self._handle_message(
            sender_id=str(from_account),
            chat_id=chat_id,
            content=content,
            media=media_paths or None,
            metadata={
                "msg_id": msg_id,
                "is_group": bool(group_code),
                "group_code": group_code,
                "group_name": group_name,
                "nickname": sender_nickname,
            },
            is_dm=is_dm,
        )

    # ------------------------------------------------------------------
    # Outbound
    # ------------------------------------------------------------------

    async def send(self, msg: OutboundMessage) -> None:
        """Send a message through the Yuanbao channel."""
        if self._ws is None:
            raise RuntimeError("yuanbao: not connected")

        if not msg.chat_id:
            logger.error("yuanbao: empty chat_id")
            return

        # Parse chat_id: "group:<code>" or "direct:<account>"
        is_group = msg.chat_id.startswith("group:")
        target = msg.chat_id.split(":", 1)[1] if ":" in msg.chat_id else msg.chat_id

        # Build msg_body
        msg_body: list[dict] = []

        # Check if content is a sticker request: [sticker:name] or [表情:name]
        text = (msg.content or "").strip()
        sticker_match = _STICKER_RE.match(text) if text else None
        if sticker_match:
            sticker_name = sticker_match.group(1)
            sticker = get_sticker_by_name(sticker_name)
            if sticker:
                msg_body = build_sticker_msg_body(sticker)
            else:
                msg_body = [{"msg_type": "TIMTextElem", "msg_content": {"text": text}}]
        else:
            # Add media first
            for ref in msg.media or []:
                if seg := await self._build_media_segment(ref):
                    msg_body.append(seg)

            # Add text
            if text:
                msg_body.append({"msg_type": "TIMTextElem", "msg_content": {"text": text}})

        if not msg_body:
            return

        # Get per-chat lock for ordered sends
        lock = self._get_chat_lock(msg.chat_id)
        async with lock:
            try:
                if is_group:
                    data = encode_send_group_message(
                        group_code=target,
                        msg_body=msg_body,
                        from_account=self._bot_id,
                    )
                else:
                    data = encode_send_c2c_message(
                        to_account=target,
                        msg_body=msg_body,
                        from_account=self._bot_id,
                        msg_random=secrets.randbelow(1 << 31),
                        msg_seq=next_seq_no(),
                    )
                await self._ws.send(data)
                # Record sent text to skip delivery callbacks
                if text:
                    self._sent_msg_bodies.append(text)
                logger.info(
                    "yuanbao: sent {} to {} (text_len={}, preview={!r})",
                    "group" if is_group else "c2c",
                    target,
                    len(text),
                    text[:60],
                )
            except Exception as e:
                logger.error("yuanbao: send failed: {}", e)
                raise

    async def send_sticker(
        self,
        chat_id: str,
        sticker_name: str | None = None,
    ) -> None:
        """Send a sticker (TIMFaceElem) through the Yuanbao channel.

        Args:
            chat_id: Target chat ID (group:<code> or direct:<account>).
            sticker_name: Sticker name from STICKER_MAP. If None, sends a random sticker.

        Raises:
            RuntimeError: If not connected.
            ValueError: If the named sticker is not found.
        """
        if self._ws is None:
            raise RuntimeError("yuanbao: not connected")

        if sticker_name:
            sticker = get_sticker_by_name(sticker_name)
            if sticker is None:
                raise ValueError(f"Sticker not found: {sticker_name!r}")
            msg_body = build_sticker_msg_body(sticker)
        else:
            sticker = get_random_sticker()
            msg_body = build_sticker_msg_body(sticker)

        is_group = chat_id.startswith("group:")
        target = chat_id.split(":", 1)[1] if ":" in chat_id else chat_id

        lock = self._get_chat_lock(chat_id)
        async with lock:
            try:
                if is_group:
                    data = encode_send_group_message(
                        group_code=target,
                        msg_body=msg_body,
                        from_account=self._bot_id,
                    )
                else:
                    data = encode_send_c2c_message(
                        to_account=target,
                        msg_body=msg_body,
                        from_account=self._bot_id,
                    )
                await self._ws.send(data)
            except Exception as e:
                logger.error("yuanbao: send_sticker failed: {}", e)
                raise

    async def _build_media_segment(self, ref: str) -> dict | None:
        """Build a media msg_body element from a file reference.

        Supports local file paths and HTTP URLs.
        """
        ref = (ref or "").strip()
        if not ref:
            return None

        # Remote URL
        if ref.startswith(("http://", "https://")):
            ok, err = validate_url_target(ref)
            if not ok:
                logger.warning("yuanbao: rejected remote media '{}': {}", ref, err)
                return None

            # Download and upload to COS
            try:
                file_bytes, content_type = await download_url(ref, max_size_mb=50)
            except Exception as e:
                logger.warning("yuanbao: failed to download media '{}': {}", ref, e)
                return None

            filename = safe_filename(ref.split("/")[-1].split("?")[0]) or "file.bin"
            return await self._upload_and_build_media(file_bytes, filename, content_type)

        # Local path
        path = Path(os.path.expanduser(ref)).resolve()
        if not path.is_file():
            logger.warning("yuanbao: local file not found: {}", path)
            return None

        try:
            file_bytes = await asyncio.to_thread(path.read_bytes)
        except OSError as e:
            logger.warning("yuanbao: failed to read local file '{}': {}", path, e)
            return None

        filename = path.name
        content_type = guess_mime_type(filename)
        return await self._upload_and_build_media(file_bytes, filename, content_type)

    async def _upload_and_build_media(self, file_bytes: bytes, filename: str, content_type: str) -> dict | None:
        """Upload file bytes to COS and build the appropriate msg_body element."""
        try:
            token_data = await _get_sign_token(self.config)
            token = token_data.get("token", "")
            bot_id = token_data.get("bot_id", "") or self._bot_id

            credentials = await get_cos_credentials(
                app_key=self.config.app_id,
                api_domain=self.config.api_domain,
                token=token,
                filename=filename,
                bot_id=bot_id,
                route_env=self.config.route_env,
            )

            file_uuid = md5_hex(file_bytes)

            upload_result = await upload_to_cos(
                file_bytes=file_bytes,
                filename=filename,
                content_type=content_type,
                credentials=credentials,
                bucket=credentials["bucketName"],
                region=credentials["region"],
            )

            is_image = content_type.startswith("image/")
            if is_image:
                body = build_image_msg_body(
                    url=upload_result["url"],
                    uuid=file_uuid,
                    filename=filename,
                    size=upload_result["size"],
                    width=upload_result.get("width", 0),
                    height=upload_result.get("height", 0),
                    mime_type=content_type,
                )
            else:
                body = build_file_msg_body(
                    url=upload_result["url"],
                    uuid=file_uuid,
                    filename=filename,
                    size=upload_result["size"],
                    mime_type=content_type,
                )
            return body[0] if body else None
        except Exception as e:
            logger.warning("yuanbao: media upload failed for '{}': {}", filename, e)
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_chat_lock(self, chat_id: str) -> asyncio.Lock:
        """Get (or create) a per-chat-id lock for serialised sends."""
        if chat_id not in self._chat_locks:
            self._chat_locks[chat_id] = asyncio.Lock()
        return self._chat_locks[chat_id]

    async def _download_media(self, url: str, media_type: str, original_name: str = "") -> str | None:
        """Download a media file from URL and save locally.

        Args:
            url: Remote URL to download from.
            media_type: ``"image"``, ``"audio"``, or ``"file"`` (used as fallback).
            original_name: Original filename from the push payload; its extension
                is preserved so downstream extractors can recognise the format.
        """
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return None
        if self._http is None:
            return None

        ok, err = validate_url_target(url)
        if not ok:
            logger.warning("yuanbao: skip media '{}': {}", url, err)
            return None

        max_bytes = 20 * 1024 * 1024
        try:
            # Resolve resource download URLs before fetching
            resolved = await _resolve_download_url(url, self.config)
            if resolved != url:
                logger.debug("yuanbao: download URL resolved: {} → {}", url, resolved)
            resp = await self._http.get(resolved, follow_redirects=False)
            if 300 <= resp.status_code < 400:
                logger.warning("yuanbao: media download redirect rejected: {}", url)
                return None
            if resp.status_code >= 400:
                logger.warning("yuanbao: media download status={} url={}", resp.status_code, url)
                return None

            data = resp.content
            if len(data) > max_bytes:
                logger.warning("yuanbao: media exceeds 20MB: {}", url)
                return None
        except Exception as e:
            logger.warning("yuanbao: media download error url={} err={}", url, e)
            return None

        from pathlib import Path as _Path

        ext = ".bin"
        if media_type == "image":
            ext = ".jpg"
        elif media_type == "audio":
            ext = ".mp3"
        # Preserve original extension so downstream extractors (docx, pdf, …)
        # can recognise the format.
        if original_name:
            orig_ext = _Path(original_name).suffix.lower()
            if orig_ext:
                ext = orig_ext
        name = f"{int(time.time() * 1000)}_{secrets.token_hex(4)}{ext}"
        path = self._media_root / name
        try:
            self._media_root.mkdir(parents=True, exist_ok=True)
            await asyncio.to_thread(path.write_bytes, data)
        except OSError as e:
            logger.warning("yuanbao: failed to save media: {}", e)
            return None
        return str(path)

    def _schedule_reconnect(self) -> None:
        """Schedule a reconnect if running and not already reconnecting."""
        if self._running:
            logger.info("yuanbao: scheduling reconnect")
            # The main loop in start() handles reconnection when _connect() raises
            # We cancel the recv task to trigger the error path
            if self._recv_task and not self._recv_task.done():
                self._recv_task.cancel()

    async def _cancel_background_loops(self) -> None:
        """Cancel heartbeat and recv tasks from the previous connection."""
        for attr in ("_heartbeat_task", "_recv_task"):
            task = getattr(self, attr, None)
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
                setattr(self, attr, None)

    async def _await_disconnect(self) -> None:
        """Block until the current connection drops (background tasks exit)."""
        watch_tasks: list[asyncio.Task] = []
        if self._recv_task is not None and not self._recv_task.done():
            watch_tasks.append(self._recv_task)
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            watch_tasks.append(self._heartbeat_task)
        if not watch_tasks:
            return
        await asyncio.wait(watch_tasks, return_when=asyncio.FIRST_COMPLETED)

    def _cancel_background_tasks(self) -> None:
        """Cancel all tracked background tasks."""
        tasks = list(self._background_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            # Don't await — just cancel and forget
            pass
        self._background_tasks.clear()
