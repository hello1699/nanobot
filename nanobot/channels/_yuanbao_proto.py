"""
yuanbao_proto.py - Yuanbao WebSocket protocol codec (pure Python).

Protocol stack:
  WebSocket frame
    └── ConnMsg (protobuf: trpc.yuanbao.conn_common.ConnMsg)
          ├── head: Head  (cmd_type, cmd, seq_no, msg_id, module, ...)
          └── data: bytes  (business payload, standard protobuf)

WebSocket carries one ConnMsg protobuf bytes per frame (no framing issues).
Implements hand-written varint / protobuf wire-format codec, no third-party
protobuf library dependency.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)

# ============================================================
# Debug switch
# ============================================================

DEBUG_MODE = False


def _dbg(label: str, data: bytes) -> None:
    if DEBUG_MODE:
        hex_str = " ".join(f"{b:02x}" for b in data[:64])
        ellipsis = "..." if len(data) > 64 else ""
        logger.debug("[yuanbao_proto] %s (%dB): %s", label, len(data), hex_str + ellipsis)


# ============================================================
# Constants
# ============================================================

# conn layer message type enums (ConnMsg.Head.cmd_type)
CMD_TYPE = {
    "Request": 0,
    "Response": 1,
    "Push": 2,
    "PushAck": 3,
}

# Built-in command words
CMD = {
    "AuthBind": "auth-bind",
    "Ping": "ping",
    "Kickout": "kickout",
    "UpdateMeta": "update-meta",
}

# Built-in module names
MODULE = {
    "ConnAccess": "conn_access",
}

# biz layer service/method mapping
_BIZ_PKG = "yuanbao_openclaw_proxy"
BIZ_SERVICES = {
    "InboundMessagePush": f"{_BIZ_PKG}.InboundMessagePush",
    "SendC2CMessageReq": f"{_BIZ_PKG}.SendC2CMessageReq",
    "SendC2CMessageRsp": f"{_BIZ_PKG}.SendC2CMessageRsp",
    "SendGroupMessageReq": f"{_BIZ_PKG}.SendGroupMessageReq",
    "SendGroupMessageRsp": f"{_BIZ_PKG}.SendGroupMessageRsp",
    "QueryGroupInfoReq": f"{_BIZ_PKG}.QueryGroupInfoReq",
    "QueryGroupInfoRsp": f"{_BIZ_PKG}.QueryGroupInfoRsp",
    "GetGroupMemberListReq": f"{_BIZ_PKG}.GetGroupMemberListReq",
    "GetGroupMemberListRsp": f"{_BIZ_PKG}.GetGroupMemberListRsp",
    "SendPrivateHeartbeatReq": f"{_BIZ_PKG}.SendPrivateHeartbeatReq",
    "SendPrivateHeartbeatRsp": f"{_BIZ_PKG}.SendPrivateHeartbeatRsp",
    "SendGroupHeartbeatReq": f"{_BIZ_PKG}.SendGroupHeartbeatReq",
    "SendGroupHeartbeatRsp": f"{_BIZ_PKG}.SendGroupHeartbeatRsp",
}

# openclaw instance_id (fixed value 17)
HERMES_INSTANCE_ID = 17

# Reply Heartbeat status constants
WS_HEARTBEAT_RUNNING = 1
WS_HEARTBEAT_FINISH = 2

# ============================================================
# Sequence number generator
# ============================================================

_seq_lock = threading.Lock()
_seq_counter = 0
_SEQ_MAX = 2 ** 32 - 1


def next_seq_no() -> int:
    """Generate an incrementing sequence number (thread-safe, wraps to 0 on overflow)."""
    global _seq_counter
    with _seq_lock:
        val = _seq_counter
        _seq_counter = (_seq_counter + 1) & _SEQ_MAX
    return val


# ============================================================
# Protobuf wire-format primitives
# ============================================================

WT_VARINT = 0
WT_64BIT = 1
WT_LEN = 2
WT_32BIT = 5


def _encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as protobuf varint."""
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    out = []
    while True:
        bits = value & 0x7F
        value >>= 7
        if value:
            out.append(bits | 0x80)
        else:
            out.append(bits)
            break
    return bytes(out)


def _decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a varint from data[pos:], return (value, new_pos)."""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift >= 64:
            raise ValueError("varint too long")
    return result, pos


def _encode_field(field_number: int, wire_type: int, value: bytes) -> bytes:
    """Encode a protobuf field (tag + value)."""
    tag = (field_number << 3) | wire_type
    return _encode_varint(tag) + value


def _encode_string(s: str) -> bytes:
    """Encode a protobuf string field value (length-prefixed UTF-8)."""
    encoded = s.encode("utf-8")
    return _encode_varint(len(encoded)) + encoded


def _encode_bytes(b: bytes) -> bytes:
    """Encode a protobuf bytes field value (length-prefixed)."""
    return _encode_varint(len(b)) + b


def _encode_message(b: bytes) -> bytes:
    """Encode a nested message (length-prefixed)."""
    return _encode_varint(len(b)) + b


def _parse_fields(data: bytes) -> list[tuple[int, int, bytes | int]]:
    """
    Parse all fields of a protobuf message.

    Returns:
        [(field_number, wire_type, raw_value), ...]
    """
    fields = []
    pos = 0
    n = len(data)
    while pos < n:
        tag, pos = _decode_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x07
        if wire_type == WT_VARINT:
            val, pos = _decode_varint(data, pos)
            fields.append((field_number, wire_type, val))
        elif wire_type == WT_LEN:
            length, pos = _decode_varint(data, pos)
            val = data[pos: pos + length]
            pos += length
            fields.append((field_number, wire_type, val))
        elif wire_type == WT_64BIT:
            val = data[pos: pos + 8]
            pos += 8
            fields.append((field_number, wire_type, val))
        elif wire_type == WT_32BIT:
            val = data[pos: pos + 4]
            pos += 4
            fields.append((field_number, wire_type, val))
        else:
            raise ValueError(f"unknown wire type {wire_type} at pos {pos - 1}")
    return fields


def _fields_to_dict(fields: list) -> dict[int, list]:
    """Convert fields list to {field_number: [(wt, val), ...]} dict."""
    d: dict[int, list] = {}
    for fn, wt, val in fields:
        d.setdefault(fn, []).append((wt, val))
    return d


def _get_string(fdict: dict, fn: int, default: str = "") -> str:
    """Get the first string field from a fields dict."""
    entries = fdict.get(fn)
    if not entries:
        return default
    wt, val = entries[0]
    if wt == WT_LEN and isinstance(val, (bytes, bytearray)):
        return val.decode("utf-8", errors="replace")
    return default


def _get_varint(fdict: dict, fn: int, default: int = 0) -> int:
    """Get the first varint field from a fields dict."""
    entries = fdict.get(fn)
    if not entries:
        return default
    wt, val = entries[0]
    if wt == WT_VARINT and isinstance(val, int):
        return val
    return default


def _get_bytes(fdict: dict, fn: int, default: bytes = b"") -> bytes:
    """Get the first bytes/message field from a fields dict."""
    entries = fdict.get(fn)
    if not entries:
        return default
    wt, val = entries[0]
    if wt == WT_LEN and isinstance(val, (bytes, bytearray)):
        return bytes(val)
    return default


def _get_repeated_bytes(fdict: dict, fn: int) -> list[bytes]:
    """Get all repeated bytes/message fields."""
    entries = fdict.get(fn, [])
    return [bytes(val) for wt, val in entries if wt == WT_LEN]


# ============================================================
# ConnMsg layer codec
# ============================================================


def _encode_head(
    cmd_type: int,
    cmd: str,
    seq_no: int,
    msg_id: str,
    module: str,
    need_ack: bool = False,
    status: int = 0,
) -> bytes:
    """Encode ConnMsg.Head."""
    buf = b""
    if cmd_type != 0:
        buf += _encode_field(1, WT_VARINT, _encode_varint(cmd_type))
    if cmd:
        buf += _encode_field(2, WT_LEN, _encode_string(cmd))
    if seq_no != 0:
        buf += _encode_field(3, WT_VARINT, _encode_varint(seq_no))
    if msg_id:
        buf += _encode_field(4, WT_LEN, _encode_string(msg_id))
    if module:
        buf += _encode_field(5, WT_LEN, _encode_string(module))
    if need_ack:
        buf += _encode_field(6, WT_VARINT, _encode_varint(1))
    if status != 0:
        buf += _encode_field(10, WT_VARINT, _encode_varint(status & 0xFFFFFFFFFFFFFFFF))
    return buf


def _decode_head(data: bytes) -> dict:
    """Decode ConnMsg.Head, returns dict."""
    fdict = _fields_to_dict(_parse_fields(data))
    return {
        "cmd_type": _get_varint(fdict, 1, 0),
        "cmd": _get_string(fdict, 2, ""),
        "seq_no": _get_varint(fdict, 3, 0),
        "msg_id": _get_string(fdict, 4, ""),
        "module": _get_string(fdict, 5, ""),
        "need_ack": bool(_get_varint(fdict, 6, 0)),
        "status": _get_varint(fdict, 10, 0),
    }


def encode_conn_msg(msg_type: int, seq_no: int, data: bytes) -> bytes:
    """Encode a simple ConnMsg."""
    head_bytes = _encode_head(
        cmd_type=msg_type,
        cmd="",
        seq_no=seq_no,
        msg_id="",
        module="",
    )
    buf = _encode_field(1, WT_LEN, _encode_message(head_bytes))
    if data:
        buf += _encode_field(2, WT_LEN, _encode_bytes(data))
    _dbg("encode_conn_msg", buf)
    return buf


def decode_conn_msg(data: bytes) -> dict:
    """Decode ConnMsg, returns {msg_type, seq_no, data, head}."""
    _dbg("decode_conn_msg", data)
    fdict = _fields_to_dict(_parse_fields(data))
    head_bytes = _get_bytes(fdict, 1)
    payload = _get_bytes(fdict, 2)
    head = _decode_head(head_bytes) if head_bytes else {
        "cmd_type": 0, "cmd": "", "seq_no": 0, "msg_id": "", "module": "",
        "need_ack": False, "status": 0,
    }
    return {
        "msg_type": head["cmd_type"],
        "seq_no": head["seq_no"],
        "data": payload,
        "head": head,
    }


def encode_conn_msg_full(
    cmd_type: int,
    cmd: str,
    seq_no: int,
    msg_id: str,
    module: str,
    data: bytes,
    need_ack: bool = False,
) -> bytes:
    """
    Encode a full ConnMsg with all head fields.

    Provides more head control than encode_conn_msg.
    """
    head_bytes = _encode_head(
        cmd_type=cmd_type,
        cmd=cmd,
        seq_no=seq_no,
        msg_id=msg_id,
        module=module,
        need_ack=need_ack,
    )
    buf = _encode_field(1, WT_LEN, _encode_message(head_bytes))
    if data:
        buf += _encode_field(2, WT_LEN, _encode_bytes(data))
    _dbg("encode_conn_msg_full", buf)
    return buf


def encode_biz_msg(service: str, method: str, req_id: str, body: bytes) -> bytes:
    """Wrap business payload into ConnMsg bytes (ready to send over WebSocket).

    Matches the behaviour of buildBusinessConnMsg() in the TypeScript client.
    """
    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["Request"],
        cmd=method,
        seq_no=next_seq_no(),
        msg_id=req_id,
        module=service,
        data=body,
    )


# ============================================================
# MsgContent codec
# ============================================================


def _encode_msg_content(content: dict) -> bytes:
    buf = b""
    for fn, key in [
        (1, "text"), (2, "uuid"), (4, "data"), (5, "desc"),
        (6, "ext"), (7, "sound"), (10, "url"), (12, "file_name"),
    ]:
        v = content.get(key, "")
        if v:
            buf += _encode_field(fn, WT_LEN, _encode_string(str(v)))
    for fn, key in [(3, "image_format"), (9, "index"), (11, "file_size")]:
        v = content.get(key, 0)
        if v:
            buf += _encode_field(fn, WT_VARINT, _encode_varint(int(v)))
    for img in content.get("image_info_array") or []:
        img_buf = b""
        for ifn, ikey in [(1, "type"), (2, "size"), (3, "width"), (4, "height")]:
            iv = img.get(ikey, 0)
            if iv:
                img_buf += _encode_field(ifn, WT_VARINT, _encode_varint(int(iv)))
        url = img.get("url", "")
        if url:
            img_buf += _encode_field(5, WT_LEN, _encode_string(url))
        buf += _encode_field(8, WT_LEN, _encode_message(img_buf))
    ext_map = content.get("ext_map")
    if isinstance(ext_map, dict):
        for k, v in ext_map.items():
            entry_bytes = _encode_map_entry(str(k), str(v))
            buf += _encode_field(999, WT_LEN, _encode_message(entry_bytes))
    return buf


def _decode_msg_content(data: bytes) -> dict:
    fdict = _fields_to_dict(_parse_fields(data))
    content: dict = {}
    for fn, key in [
        (1, "text"), (2, "uuid"), (4, "data"), (5, "desc"),
        (6, "ext"), (7, "sound"), (10, "url"), (12, "file_name"),
    ]:
        v = _get_string(fdict, fn)
        if v:
            content[key] = v
    for fn, key in [(3, "image_format"), (9, "index"), (11, "file_size")]:
        v = _get_varint(fdict, fn)
        if v:
            content[key] = v
    imgs = []
    for img_bytes in _get_repeated_bytes(fdict, 8):
        ifdict = _fields_to_dict(_parse_fields(img_bytes))
        img = {}
        for ifn, ikey in [(1, "type"), (2, "size"), (3, "width"), (4, "height")]:
            iv = _get_varint(ifdict, ifn)
            if iv:
                img[ikey] = iv
        url = _get_string(ifdict, 5)
        if url:
            img["url"] = url
        if img:
            imgs.append(img)
    if imgs:
        content["image_info_array"] = imgs
    ext_map: dict[str, str] = {}
    for entry_bytes in _get_repeated_bytes(fdict, 999):
        k, v = _decode_map_entry(entry_bytes)
        if k:
            ext_map[k] = v
    if ext_map:
        content["ext_map"] = ext_map
    return content


def _encode_map_entry(key: str, value: str) -> bytes:
    """Encode a single entry of a protobuf map<string, string>."""
    buf = b""
    if key:
        buf += _encode_field(1, WT_LEN, _encode_string(str(key)))
    if value:
        buf += _encode_field(2, WT_LEN, _encode_string(str(value)))
    return buf


def _decode_map_entry(data: bytes) -> tuple[str, str]:
    """Decode a single entry of a protobuf map<string, string>, returns (key, value)."""
    fdict = _fields_to_dict(_parse_fields(data))
    return _get_string(fdict, 1), _get_string(fdict, 2)


def _decode_msg_body_element(data: bytes) -> dict:
    """Decode a single MsgBody element (official: msgType as string, field 1)."""
    fdict = _fields_to_dict(_parse_fields(data))
    msg_type = _get_string(fdict, 1)  # String per official schema
    content_bytes = _get_bytes(fdict, 2)
    content = _decode_msg_content(content_bytes) if content_bytes else {}
    return {
        "msg_type": msg_type,
        "msg_content": content,
    }


def _decode_msg_body_element_json(data: bytes) -> dict:
    """Decode a MsgBody element by JSON-deserialising the data field."""
    fdict = _fields_to_dict(_parse_fields(data))
    msg_type = _get_varint(fdict, 1)
    content_bytes = _get_bytes(fdict, 2)
    content: dict = {}
    if content_bytes:
        try:
            content = json.loads(content_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            content = {"text": content_bytes.decode("utf-8", errors="replace")}
    return {
        "msg_type": msg_type,
        "msg_content": content,
    }


# ============================================================
# Inbound message push decoding
# ============================================================


def decode_inbound_push(data: bytes) -> Optional[dict]:
    """
    Parse inbound push message business payload (InboundMessagePush proto bytes).

    Returns a dict with fields: from_account, to_account, group_code, group_name,
    msg_key, msg_id, msg_seq, msg_random, msg_time, sender_nickname, msg_body,
    callback_command, cloud_custom_data, bot_owner_id, claw_msg_type,
    private_from_group_code, trace_id.

    Returns None on parse failure.
    """
    try:
        _dbg("decode_inbound_push input", data)
        fdict = _fields_to_dict(_parse_fields(data))

        msg_body = []
        for el_bytes in _get_repeated_bytes(fdict, 13):
            msg_body.append(_decode_msg_body_element(el_bytes))

        log_ext_bytes = _get_bytes(fdict, 20)
        trace_id = _decode_log_ext(log_ext_bytes).get("trace_id", "") if log_ext_bytes else ""

        result: dict = {
            "callback_command": _get_string(fdict, 1),
            "from_account": _get_string(fdict, 2),
            "to_account": _get_string(fdict, 3),
            "sender_nickname": _get_string(fdict, 4),
            "group_id": _get_string(fdict, 5),
            "group_code": _get_string(fdict, 6),
            "group_name": _get_string(fdict, 7),
            "msg_seq": _get_varint(fdict, 8),
            "msg_random": _get_varint(fdict, 9),
            "msg_time": _get_varint(fdict, 10),
            "msg_key": _get_string(fdict, 11),
            "msg_id": _get_string(fdict, 12),
            "msg_body": msg_body,
            "cloud_custom_data": _get_string(fdict, 14),
            "event_time": _get_varint(fdict, 15),
            "bot_owner_id": _get_string(fdict, 16),
            "claw_msg_type": _get_varint(fdict, 18),
            "private_from_group_code": _get_string(fdict, 19),
            "trace_id": trace_id,
        }
        return {k: v for k, v in result.items() if v or k in {"msg_body", "msg_seq"}}
    except Exception as e:
        # Data may be JSON (callback pushes) rather than protobuf —
        # caller should fall back to JSON parsing.  Log at debug level
        # since this is an expected code path, not an error.
        logger.debug(
            "[yuanbao_proto] decode_inbound_push failed: %s — first 64 bytes: %s",
            e,
            " ".join(f"{b:02x}" for b in data[:64]),
        )
        return None


def _decode_log_ext(data: bytes) -> dict:
    """Decode LogExt (field 20) to extract trace_id."""
    fdict = _fields_to_dict(_parse_fields(data))
    return {"trace_id": _get_string(fdict, 1)}


# ============================================================
# Send message encoding
# ============================================================


def _encode_send_c2c_req(
    to_account: str,
    from_account: str,
    msg_body: list,
    msg_id: str = "",
    msg_random: int = 0,
    msg_seq: Optional[int] = None,
    group_code: str = "",
    trace_id: str = "",
) -> bytes:
    """
    Encode SendC2CMessageReq proto bytes.

    Official field layout (biz.json):
      1: msgId      (string)
      2: toAccount   (string)
      3: fromAccount (string)
      4: msgRandom   (uint32)
      5: msgBody     (repeated MsgBodyElement)
      6: groupCode   (string)
      7: msgSeq      (uint64)
      8: logExt      (LogInfoExt { traceId: string })
    """
    buf = b""
    if msg_id:
        buf += _encode_field(1, WT_LEN, _encode_string(msg_id))
    if to_account:
        buf += _encode_field(2, WT_LEN, _encode_string(to_account))
    if from_account:
        buf += _encode_field(3, WT_LEN, _encode_string(from_account))
    if msg_random:
        buf += _encode_field(4, WT_VARINT, _encode_varint(msg_random))
    for el in msg_body:
        el_bytes = _encode_msg_body_element(el)
        if el_bytes:
            buf += _encode_field(5, WT_LEN, _encode_message(el_bytes))
    if group_code:
        buf += _encode_field(6, WT_LEN, _encode_string(group_code))
    if msg_seq is not None:
        buf += _encode_field(7, WT_VARINT, _encode_varint(msg_seq))
    if trace_id:
        # logExt { traceId: trace_id }
        log_ext_buf = _encode_field(1, WT_LEN, _encode_string(trace_id))
        buf += _encode_field(8, WT_LEN, _encode_message(log_ext_buf))
    return buf


def _encode_send_group_req(
    group_code: str,
    from_account: str,
    msg_body: list,
    msg_id: str = "",
    to_account: str = "",
    random: str = "",
    msg_seq: Optional[int] = None,
    ref_msg_id: str = "",
    trace_id: str = "",
) -> bytes:
    """
    Encode SendGroupMessageReq proto bytes.

    Official field layout (biz.json):
      1: msgId      (string)
      2: groupCode  (string)
      3: fromAccount (string)
      4: toAccount   (string)
      5: random     (string)
      6: msgBody    (repeated MsgBodyElement)
      7: refMsgId   (string)
      8: msgSeq     (uint64)
      9: logExt     (LogInfoExt { traceId: string })
    """
    buf = b""
    if msg_id:
        buf += _encode_field(1, WT_LEN, _encode_string(msg_id))
    if group_code:
        buf += _encode_field(2, WT_LEN, _encode_string(group_code))
    if from_account:
        buf += _encode_field(3, WT_LEN, _encode_string(from_account))
    if to_account:
        buf += _encode_field(4, WT_LEN, _encode_string(to_account))
    if random:
        buf += _encode_field(5, WT_LEN, _encode_string(random))
    for el in msg_body:
        el_bytes = _encode_msg_body_element(el)
        if el_bytes:
            buf += _encode_field(6, WT_LEN, _encode_message(el_bytes))
    if ref_msg_id:
        buf += _encode_field(7, WT_LEN, _encode_string(ref_msg_id))
    if msg_seq is not None:
        buf += _encode_field(8, WT_VARINT, _encode_varint(msg_seq))
    if trace_id:
        log_ext_buf = _encode_field(1, WT_LEN, _encode_string(trace_id))
        buf += _encode_field(9, WT_LEN, _encode_message(log_ext_buf))
    return buf


def _encode_msg_body_element(el: dict) -> bytes:
    """Encode a single MsgBody element dict into protobuf bytes.

    Input format: {"msg_type": "TIMTextElem", "msg_content": {"text": "hello"}}

    Official MsgBodyElement field layout (field 1 = msgType as STRING):
      1: msgType    (string) — e.g. "TIMTextElem"
      2: msgContent (MsgContent nested message)
    """
    buf = b""
    msg_type: str = el.get("msg_type", "TIMTextElem")
    msg_content: dict = el.get("msg_content", {})

    # Field 1: msgType as STRING (official schema)
    buf += _encode_field(1, WT_LEN, _encode_string(msg_type))

    # Field 2: msgContent (nested MsgContent message)
    content_bytes = _encode_msg_content(msg_content)
    buf += _encode_field(2, WT_LEN, _encode_bytes(content_bytes))
    return buf


# ============================================================
# SendC2CMessage response decoding
# ============================================================


def decode_send_c2c_rsp(data: bytes) -> dict:
    """
    Decode SendC2CMessageRsp proto bytes.

    Expected fields:
      1: result (int32)   — business result code (0 = success)
      2: err_msg (string) — error message or result info

    Returns a dict with 'result' and 'err_msg' keys.
    """
    try:
        fdict = _fields_to_dict(_parse_fields(data))
        result = _get_varint(fdict, 1, -1)
        err_msg = _get_string(fdict, 2, "")
        return {"result": result, "err_msg": err_msg}
    except Exception as e:
        return {"result": -1, "err_msg": f"decode failed: {e}"}


def encode_send_c2c_message(
    to_account: str,
    msg_body: list,
    from_account: str,
    msg_id: str = "",
    msg_random: int = 0,
    msg_seq: Optional[int] = None,
    group_code: str = "",
    trace_id: str = "",
) -> bytes:
    """Encode a C2C send-message request and return full ConnMsg bytes.

    Args:
        to_account: recipient account
        msg_body: list of {"msg_type": str, "msg_content": dict}
        from_account: sender account (the bot account)
        msg_id: unique message ID
        msg_random: random number for de-duplication
        msg_seq: message sequence number
        group_code: for "private chat from group" case
        trace_id: request tracing ID

    Returns:
        ConnMsg bytes ready to send over WebSocket
    """
    biz_bytes = _encode_send_c2c_req(
        to_account=to_account,
        from_account=from_account,
        msg_body=msg_body,
        msg_id=msg_id,
        msg_random=msg_random,
        msg_seq=msg_seq,
        group_code=group_code,
        trace_id=trace_id,
    )
    _dbg("encode_send_c2c biz payload", biz_bytes)
    req_id = msg_id or f"c2c_{next_seq_no()}"
    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["Request"],
        cmd="send_c2c_message",
        seq_no=next_seq_no(),
        msg_id=req_id,
        module=_BIZ_PKG,
        data=biz_bytes,
    )


def encode_send_group_message(
    group_code: str,
    msg_body: list,
    from_account: str,
    msg_id: str = "",
    to_account: str = "",
    random: str = "",
    msg_seq: Optional[int] = None,
    ref_msg_id: str = "",
    trace_id: str = "",
) -> bytes:
    """Encode a group send-message request and return full ConnMsg bytes.

    Args:
        group_code: group ID
        msg_body: list of message-body elements
        from_account: sender account (the bot account)
        msg_id: unique message ID
        to_account: targeted recipient (usually empty)
        random: random string for de-duplication
        msg_seq: message sequence number
        ref_msg_id: ID of the referenced (quoted) message
        trace_id: request tracing ID

    Returns:
        ConnMsg bytes ready to send over WebSocket
    """
    biz_bytes = _encode_send_group_req(
        group_code=group_code,
        from_account=from_account,
        msg_body=msg_body,
        msg_id=msg_id,
        to_account=to_account,
        random=random,
        msg_seq=msg_seq,
        ref_msg_id=ref_msg_id,
        trace_id=trace_id,
    )
    _dbg("encode_send_group biz payload", biz_bytes)
    req_id = msg_id or f"grp_{next_seq_no()}"
    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["Request"],
        cmd="send_group_message",
        seq_no=next_seq_no(),
        msg_id=req_id,
        module=_BIZ_PKG,
        data=biz_bytes,
    )


# ============================================================
# AuthBind / Ping / PushAck
# ============================================================


def encode_auth_bind(
    biz_id: str,
    uid: str,
    source: str,
    token: str,
    msg_id: str,
    app_version: str = "",
    operation_system: str = "",
    bot_version: str = "",
    route_env: str = "",
) -> bytes:
    """Build auth-bind request ConnMsg bytes.

    AuthBindReq fields:
      1: biz_id (string)
      2: auth_info (AuthInfo: uid=1, source=2, token=3)
      3: device_info (DeviceInfo: app_version=1, os=2, instance_id=10, bot_version=24)
      5: env_name (string)
    """
    auth_buf = (
        _encode_field(1, WT_LEN, _encode_string(uid))
        + _encode_field(2, WT_LEN, _encode_string(source))
        + _encode_field(3, WT_LEN, _encode_string(token))
    )
    dev_buf = b""
    if app_version:
        dev_buf += _encode_field(1, WT_LEN, _encode_string(app_version))
    if operation_system:
        dev_buf += _encode_field(2, WT_LEN, _encode_string(operation_system))
    dev_buf += _encode_field(10, WT_LEN, _encode_string(str(HERMES_INSTANCE_ID)))
    if bot_version:
        dev_buf += _encode_field(24, WT_LEN, _encode_string(bot_version))

    req_buf = (
        _encode_field(1, WT_LEN, _encode_string(biz_id))
        + _encode_field(2, WT_LEN, _encode_message(auth_buf))
        + _encode_field(3, WT_LEN, _encode_message(dev_buf))
    )
    if route_env:
        req_buf += _encode_field(5, WT_LEN, _encode_string(route_env))

    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["Request"],
        cmd=CMD["AuthBind"],
        seq_no=next_seq_no(),
        msg_id=msg_id,
        module=MODULE["ConnAccess"],
        data=req_buf,
    )


def encode_ping(msg_id: str) -> bytes:
    """Build ping request ConnMsg bytes (PingReq is an empty message)."""
    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["Request"],
        cmd=CMD["Ping"],
        seq_no=next_seq_no(),
        msg_id=msg_id,
        module=MODULE["ConnAccess"],
        data=b"",
    )


def encode_push_ack(original_head: dict) -> bytes:
    """Build push ACK response."""
    return encode_conn_msg_full(
        cmd_type=CMD_TYPE["PushAck"],
        cmd=original_head.get("cmd", ""),
        seq_no=next_seq_no(),
        msg_id=original_head.get("msg_id", ""),
        module=original_head.get("module", ""),
        data=b"",
    )


# ============================================================
# Heartbeat encoding
# ============================================================


def encode_send_private_heartbeat(
    from_account: str,
    to_account: str,
    heartbeat: int = WS_HEARTBEAT_RUNNING,
) -> bytes:
    """Encode SendPrivateHeartbeatReq, returns full ConnMsg bytes."""
    buf = (
        _encode_field(1, WT_LEN, _encode_string(from_account))
        + _encode_field(2, WT_LEN, _encode_string(to_account))
        + _encode_field(3, WT_VARINT, _encode_varint(heartbeat))
    )
    req_id = f"hb_priv_{next_seq_no()}"
    return encode_biz_msg(
        service=_BIZ_PKG,
        method="send_private_heartbeat",
        req_id=req_id,
        body=buf,
    )


def encode_send_group_heartbeat(
    from_account: str,
    group_code: str,
    heartbeat: int = WS_HEARTBEAT_RUNNING,
    send_time: int = 0,
) -> bytes:
    """Encode SendGroupHeartbeatReq, returns full ConnMsg bytes."""
    import time as _time

    ts = send_time or int(_time.time() * 1000)
    buf = (
        _encode_field(1, WT_LEN, _encode_string(from_account))
        + _encode_field(2, WT_LEN, _encode_string(""))
        + _encode_field(3, WT_LEN, _encode_string(group_code))
        + _encode_field(4, WT_VARINT, _encode_varint(ts))
        + _encode_field(5, WT_VARINT, _encode_varint(heartbeat))
    )
    req_id = f"hb_grp_{next_seq_no()}"
    return encode_biz_msg(
        service=_BIZ_PKG,
        method="send_group_heartbeat",
        req_id=req_id,
        body=buf,
    )
