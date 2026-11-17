"""Independent WHATWG IPv4 parser, implemented from the URL Standard.

Used to cross-check the Node reference for numeric hosts without trusting Node
for those cases.  Returns a dotted-quad string, or None when the host does not
end in a number / fails validation.
"""

from __future__ import annotations

from urllib.parse import unquote


def _is_number(token: str) -> int | None:
    if token == "":
        return None
    if token.startswith(("0x", "0X")):
        body = token[2:]
        if body == "":
            return 0
        if all(c in "0123456789abcdefABCDEF" for c in body):
            return int(body, 16)
        return None
    if token.startswith("0") and len(token) > 1:
        if all(c in "01234567" for c in token):
            return int(token, 8)
        return None
    if token.isdigit():
        return int(token, 10)
    return None


def parse_ipv4(host: str) -> str | None:
    """WHATWG 'IPv4 parser' host in, dotted-quad out (or None)."""
    if host is None:
        return None
    decoded = unquote(host)
    parts = decoded.split(".")
    if parts and parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if not parts or len(parts) > 4:
        return None
    numbers: list[int] = []
    for part in parts:
        value = _is_number(part)
        if value is None:
            return None
        numbers.append(value)
    if any(n > 255 for n in numbers[:-1]):
        return None
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    ipv4 = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        ipv4 += n * 256 ** (3 - i)
    return ".".join(str((ipv4 >> shift) & 0xFF) for shift in (24, 16, 8, 0))