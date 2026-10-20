"""SSRF-resistant outbound JSON requests, pinned to validated DNS answers."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx


def validate_url(url, private_hosts=()):
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        raise ValueError("仅支持无内嵌凭证的 HTTP(S) 地址")
    if parts.fragment or parts.query:
        raise ValueError("地址不得包含片段或查询参数")
    host = parts.hostname.lower()
    # Plain HTTP credentials are permitted only for explicitly authorized intranet targets.
    if parts.scheme != "https" and host not in private_hosts:
        raise ValueError("外部目标必须使用 HTTPS；内网目标需部署白名单授权")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("端口无效") from exc
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = sorted({item[4][0] for item in addresses})
    if not ips:
        raise ValueError("目标域名无可用地址")
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global and host not in private_hosts:
            raise ValueError("私有、保留或本机地址未被授权")
        if ip.is_unspecified or ip.is_multicast:
            raise ValueError("禁止未指定地址和组播地址")
        if str(ip) == "169.254.169.254":
            raise ValueError("禁止访问实例元数据地址")
    ip = ips[0]
    netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", "", ""))
    return pinned, {"Host": parts.netloc}, {"sni_hostname": host}


async def post_json(url, payload, private_hosts=(), credential="", headers=None, expect_json=True):
    pinned, host_headers, extensions = await asyncio.to_thread(validate_url, url, private_hosts)
    all_headers = {**host_headers, **(headers or {})}
    if credential:
        all_headers["Authorization"] = f"Bearer {credential}"
    async with httpx.AsyncClient(timeout=20, trust_env=False, follow_redirects=False) as client:
        async with client.stream("POST", pinned, json=payload, headers=all_headers, extensions=extensions) as response:
            if response.status_code < 200 or response.status_code >= 300:
                raise ValueError(f"upstream_http_{response.status_code}")
            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > 2 * 1024 * 1024:
                    raise ValueError("上游响应超过 2 MiB")
            if not content or not expect_json:
                return {}, response.status_code
            return json.loads(content), response.status_code
