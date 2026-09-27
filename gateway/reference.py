"""超期记录的仅审计引用句柄：确定性、可复现、不含任何原始字段值。"""

from __future__ import annotations

import hashlib
import hmac


def reference_handle(record_id: str, policy_version: int, key: bytes) -> str:
    """生成仅审计引用句柄。

    句柄由 (记录标识, 策略版本) 经 HMAC-SHA256 派生：
    - 同一记录在同一策略版本下稳定可复现；
    - 策略版本变化后新旧句柄可区分；
    - 不含、也不可反推任何原始敏感字段值。
    """
    if not key:
        raise ValueError("reference-key-missing")
    msg = f"audit-ref|{record_id}|v{policy_version}".encode()
    digest = hmac.new(key, msg, hashlib.sha256).hexdigest()
    return f"ref_{digest[:24]}"
