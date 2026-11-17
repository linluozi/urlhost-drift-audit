"""Host extraction for three Python URL parsers plus the WHATWG reference.

The WHATWG reference is Node's built-in ``URL`` (node >= 18).  It is invoked
once for the whole corpus so process startup is not paid per URL.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

PY_PARSERS = ("stdlib", "urllib3", "yarl")
REFERENCE = "whatwg_node"

_NODE_SCRIPT = Path(__file__).with_name("whatwg_ref.js")


def _node_bin() -> str | None:
    return shutil.which("node")


def parse_with_stdlib(url: str) -> dict:
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url)
    except Exception as exc:  # pragma: no cover - urlsplit rarely raises
        return {"ok": False, "error": type(exc).__name__}
    host = parts.hostname
    if host is None:
        return {"ok": True, "host": None, "scheme": parts.scheme, "port": None}
    try:
        port = parts.port
    except ValueError:
        port = None
    return {"ok": True, "host": host, "scheme": parts.scheme, "port": port}


def parse_with_urllib3(url: str) -> dict:
    from urllib3.util import parse_url

    try:
        parts = parse_url(url)
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}
    host = parts.host
    if host == "":
        host = None
    return {"ok": True, "host": host, "scheme": parts.scheme, "port": parts.port}


def parse_with_yarl(url: str) -> dict:
    import yarl

    try:
        u = yarl.URL(url)
    except Exception as exc:
        return {"ok": False, "error": type(exc).__name__}
    host = u.host
    if host == "":
        host = None
    return {"ok": True, "host": host, "scheme": u.scheme, "port": u.port}


PY_FUNCS = {
    "stdlib": parse_with_stdlib,
    "urllib3": parse_with_urllib3,
    "yarl": parse_with_yarl,
}


def parse_python(url: str) -> dict[str, dict]:
    return {name: PY_FUNCS[name](url) for name in PY_PARSERS}


def parse_reference(urls: list[str]) -> dict[str, dict]:
    """Return WHATWG results keyed by URL.  All URLs in one node call."""
    node = _node_bin()
    if node is None:
        return {u: {"ok": False, "error": "node_missing"} for u in urls}
    payload = json.dumps(urls)
    proc = subprocess.run(
        [node, str(_NODE_SCRIPT)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"node reference failed rc={proc.returncode}: {proc.stderr[:400]}")
    rows = json.loads(proc.stdout)
    if len(rows) != len(urls):
        raise RuntimeError(f"node returned {len(rows)} rows for {len(urls)} urls")
    return dict(zip(urls, rows))


def parser_versions() -> dict[str, str]:
    import platform

    import urllib3
    import yarl

    node = _node_bin()
    node_version = "missing"
    if node:
        node_version = subprocess.run(
            [node, "--version"], capture_output=True, text=True, timeout=10
        ).stdout.strip()
    return {
        "python": platform.python_version(),
        "urllib3": urllib3.__version__,
        "yarl": yarl.__version__,
        "node": node_version,
    }