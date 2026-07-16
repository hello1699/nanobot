"""
yuanbao_media.py — Yuanbao platform media processing module.

Provides COS upload, file download, TIM media message building.
Uses httpx to replace cos-nodejs-sdk-v5, avoiding extra SDK dependency.

COS upload flow:
  1. Call genUploadInfo to get temporary credentials
  2. Use HMAC-SHA1 to sign Authorization header
  3. HTTP PUT upload to COS

TIM message body building:
  - build_image_msg_body() -> TIMImageElem
  - build_file_msg_body()  -> TIMFileElem
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import struct
import time
import urllib.parse
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# ============ Constants ============

UPLOAD_INFO_PATH = "/api/resource/genUploadInfo"
DEFAULT_API_DOMAIN = "yuanbao.tencent.com"
DEFAULT_MAX_SIZE_MB = 50

COS_USE_ACCELERATE = True

# MIME -> image_format number (TIM protocol fields)
_MIME_TO_IMAGE_FORMAT: dict[str, int] = {
    "image/jpeg": 1,
    "image/jpg": 1,
    "image/gif": 2,
    "image/png": 3,
    "image/bmp": 4,
    "image/webp": 255,
    "image/heic": 255,
    "image/tiff": 255,
}

_EXT_TO_MIME: dict[str, str] = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
    ".mp4": "video/mp4",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".zip": "application/zip",
    ".txt": "text/plain",
    ".md": "text/markdown",
}


def guess_mime_type(filename: str) -> str:
    """Guess MIME type from file extension, default to application/octet-stream."""
    ext = os.path.splitext(filename)[1].lower()
    return _EXT_TO_MIME.get(ext, "application/octet-stream")


def md5_hex(data: bytes) -> str:
    """Compute MD5 hex digest (lowercase)."""
    return hashlib.md5(data).hexdigest()


# ============ Download ============


async def download_url(url: str, max_size_mb: int = DEFAULT_MAX_SIZE_MB) -> tuple[bytes, str]:
    """Download a file from URL, returns (bytes, content_type).

    Raises ValueError on failure.
    """
    max_bytes = max_size_mb * 1024 * 1024
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        data = resp.content
        if len(data) > max_bytes:
            raise ValueError(f"File too large: {len(data)} bytes > {max_bytes} bytes max")
        content_type = resp.headers.get("content-type", "application/octet-stream")
        return data, content_type


# ============ COS credentials ============


async def get_cos_credentials(
    app_key: str,
    api_domain: str,
    token: str,
    filename: str,
    bot_id: str,
    route_env: str = "",
) -> dict:
    """Get COS upload credentials from Yuanbao API.

    Returns:
        dict with keys: bucketName, region, tmpSecretId, tmpSecretKey, sessionToken, url
    """
    url = f"{api_domain.rstrip('/')}{UPLOAD_INFO_PATH}"
    headers = {
        "Content-Type": "application/json",
        "token": token,
    }
    if route_env:
        headers["X-Route-Env"] = route_env

    payload = {
        "app_key": app_key,
        "file_name": filename,
        "bot_id": bot_id,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        body = resp.json()
        if body.get("code") != 0:
            raise ValueError(f"genUploadInfo failed: code={body.get('code')} msg={body.get('msg')}")
        data = body.get("data", {})
        logger.info("COS credentials obtained: bucket=%s region=%s", data.get("bucketName"), data.get("region"))
        return data


# ============ COS upload ============

_COS_TIMEOUT = 120.0


def _cos_sign(
    key: str,
    msg: str,
    algorithm: str = "sha1",
) -> bytes:
    """HMAC-SHA1 (or SHA256) signing."""
    if algorithm == "sha256":
        return hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest()
    return hmac.new(key.encode(), msg.encode(), hashlib.sha1).digest()


def _build_cos_authorization(
    method: str,
    path: str,
    credentials: dict,
    key_time: str,
) -> str:
    """Build COS HMAC-SHA1 Authorization header.

    COS V5 signature algorithm:
      1. SignKey = HMAC-SHA1(secretKey, keyTime)
      2. StringToSign = {method}\\n{path}\\n\\nhost={host}\\n
      3. Signature = HMAC-SHA1(SignKey, StringToSign)
      4. Authorization = q-sign-algorithm=sha1&q-ak={ak}&q-sign-time=...&...
    """
    tmp_secret_id = credentials["tmpSecretId"]
    tmp_secret_key = credentials["tmpSecretKey"]
    session_token = credentials.get("sessionToken", "")

    # Parse COS URL from credentials
    cos_url = credentials.get("url", "")
    parsed = urllib.parse.urlparse(cos_url)
    host = parsed.netloc

    sign_key = _cos_sign(tmp_secret_key, key_time)
    string_to_sign = f"{method}\n{path}\n\nhost={host}\n"
    signature = _cos_sign(sign_key, string_to_sign)

    auth = (
        f"q-sign-algorithm=sha1"
        f"&q-ak={tmp_secret_id}"
        f"&q-sign-time={key_time}"
        f"&q-key-time={key_time}"
        f"&q-header-list=host"
        f"&q-url-param-list="
        f"&q-signature={signature.hex()}"
    )

    return auth


async def upload_to_cos(
    file_bytes: bytes,
    filename: str,
    content_type: str,
    credentials: dict,
    bucket: str,
    region: str,
) -> dict:
    """Upload file bytes to Tencent COS.

    Returns:
        dict with keys: url, size, width, height
    """
    cos_url = credentials.get("url", "")

    # Use global accelerated endpoint if available
    if COS_USE_ACCELERATE and bucket and region:
        cos_url = f"https://{bucket}.cos.accelerate.tencent.com"

    path = f"/{urllib.parse.quote(filename)}"

    # Key time & credential scope
    current = int(time.time())
    key_time = f"{current};{current + 3600}"

    authorization = _build_cos_authorization(
        method="put",
        path=path,
        credentials=credentials,
        key_time=key_time,
    )

    session_token = credentials.get("sessionToken", "")
    headers = {
        "Authorization": authorization,
        "Content-Type": content_type,
        "x-cos-security-token": session_token,
        "Host": urllib.parse.urlparse(cos_url).netloc,
    }

    upload_url = f"{cos_url}{path}"

    async with httpx.AsyncClient(timeout=_COS_TIMEOUT) as client:
        resp = await client.put(upload_url, content=file_bytes, headers=headers)
        resp.raise_for_status()
        logger.info("COS upload success: %s (%d bytes)", filename, len(file_bytes))

    result: dict = {
        "url": upload_url,
        "size": len(file_bytes),
        "width": 0,
        "height": 0,
    }

    # Detect image dimensions for image types
    if content_type and content_type.startswith("image/"):
        _w, _h = _guess_image_dimensions(file_bytes, content_type)
        result["width"] = _w
        result["height"] = _h

    return result


def _guess_image_dimensions(data: bytes, mime: str) -> tuple[int, int]:
    """Lightweight image dimension guesser without external libraries.

    Handles JPEG, PNG, GIF, BMP headers. Returns (0, 0) if parsing fails.
    """
    if mime == "image/png" and len(data) >= 24:
        _, w, h = struct.unpack(">III", data[16:28])
        # PNG stores width/height as (w-1, h-1) in IHDR
        return w, h
    if mime in ("image/jpeg", "image/jpg") and len(data) > 4:
        pos = 2
        while pos + 8 < len(data):
            if data[pos] == 0xFF and data[pos + 1] == 0xC0:
                h = struct.unpack(">H", data[pos + 5:pos + 7])[0]
                w = struct.unpack(">H", data[pos + 7:pos + 9])[0]
                return w, h
            seg_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
            pos += seg_len + 2
    if mime == "image/gif" and len(data) >= 10:
        w = struct.unpack("<H", data[6:8])[0]
        h = struct.unpack("<H", data[8:10])[0]
        return w, h
    if mime == "image/bmp" and len(data) >= 26:
        w = struct.unpack("<I", data[18:22])[0]
        h = abs(struct.unpack("<i", data[22:26])[0])
        return w, h
    if mime == "image/webp" and len(data) >= 30:
        # WebP: RIFF header, file size, 'WEBP', then VP8/VP8L/VP8X
        if data[12:16] == b"VP8 " and len(data) >= 30:
            w = struct.unpack("<H", data[26:28])[0] & 0x3FFF
            h = struct.unpack("<H", data[28:30])[0] & 0x3FFF
            return w, h
        if data[12:16] == b"VP8L" and len(data) >= 25:
            bits = struct.unpack("<I", data[21:25])[0]
            w = (bits & 0x3FFF) + 1
            h = ((bits >> 14) & 0x3FFF) + 1
            return w, h
        if data[12:16] == b"VP8X" and len(data) >= 30:
            w = struct.unpack("<I", data[24:28])[0] & 0x00FFFFFF
            h = struct.unpack("<I", data[26:30])[0] & 0x00FFFFFF
            return w, h
    return 0, 0


# ============ TIM message body builders ============


def build_image_msg_body(
    url: str,
    uuid: str,
    filename: str,
    size: int,
    width: int,
    height: int,
    mime_type: str = "image/png",
) -> list[dict]:
    """Build TIMImageElem message body.

    Returns:
        [{"msg_type": "TIMImageElem", "msg_content": {...}}]
    """
    img_format = _MIME_TO_IMAGE_FORMAT.get(mime_type, 255)

    content = {
        "uuid": uuid,
        "image_format": img_format,
        "file_size": size,
        "width": width or 0,
        "height": height or 0,
        "file_name": filename,
        "url": url,
        "ext": f"format:{img_format}",
    }
    return [{"msg_type": "TIMImageElem", "msg_content": content}]


def build_file_msg_body(
    url: str,
    uuid: str,
    filename: str,
    size: int,
    mime_type: str = "application/octet-stream",
) -> list[dict]:
    """Build TIMFileElem message body.

    Returns:
        [{"msg_type": "TIMFileElem", "msg_content": {...}}]
    """
    content = {
        "uuid": uuid,
        "file_size": size,
        "file_name": filename,
        "url": url,
        "ext": mime_type,
        "desc": f"file_{filename}",
    }
    return [{"msg_type": "TIMFileElem", "msg_content": content}]
