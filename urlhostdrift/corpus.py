"""Deterministic adversarial URL corpus for host-normalization differentials."""

from __future__ import annotations

import hashlib
import json
import random

SEED = 20261117

HOSTS = [
    "good.com",
    "evil.com",
    "sub.good.com",
    "example.com",
    "GOOD.com",
    "good.com.",
    "localhost",
    "127.0.0.1",
    "127.0.0.1.",
    "127.1",
    "127.0.0.1%2e",
    "0177.0.0.1",
    "0177.1",
    "2130706433",
    "0x7f.1",
    "0",
    "0300.0250.0001.0001",
    "%31%32%37.0.0.1",
    "ex%41mple.com",
    "good.com%00.evil.com",
    "exa mple.com",
    "。",
    "[::1]",
    "[0:0:0:0:0:0:0:1]",
    "[::ffff:127.0.0.1]",
    "mail.good.com",
    "mail.evil.com",
    "good.com%2f.evil.com",
    "good.com\\evil.com",
    "good.com\t.evil.com",
    "good.com\nevil.com",
    "％67ood.com",
    "good。com",
    "good．com",
    "good｡com",
]

TEMPLATES = [
    "http://{h}/",
    "http://{h}:80/",
    "http://{h}:8080/",
    "http://{h}/path?q=1",
    "https://{h}/x",
    "HTTP://{h}/",
    "ftp://{h}/f",
    "ws://{h}/s",
    "http://user@{h}/",
    "http://user@{h}@evil.com/",
    "http://{h}@evil.com/",
    "http://evil.com@{h}/",
    "http://{h}\\@evil.com/",
    "http://evil.com\\@{h}/",
    "http://{h}\\/evil.com/",
    "http://good.com\\@{h}/",
    "http://good.com@{h}/",
    "http://{h}#@evil.com/",
    "http://{h}?@evil.com/",
    "http:////{h}/",
    "http:///{h}/",
    "http://{h}\t.evil.com/",
    "http://{h}\n.evil.com/",
    "http://{h}:99999/",
    "http://{h}/%2e%2e/",
]

CURATED = [
    "http://evil.com\\@good.com/",
    "http://good.com\\@evil.com/",
    "http://example.com\\@evil.com/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "http://0x7f.1/",
    "http://127.1/",
    "http://0/",
    "http://0300.0250.0001.0001/",
    "http://127.0.0.1./",
    "http://127.0.0.1%2e/",
    "http://%31%32%37.0.0.1/",
    "http://ex%41mple.com/",
    "http://。/",
    "http://good。com/",
    "http://GOOD.com./",
    "http://[0:0:0:0:0:0:0:1]/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://user@/",
    "http:///evil.com/",
    "http:////evil.com/",
    "http://good.com:80@evil.com/",
    "http://exa mple.com/",
    "http://good.com%00.evil.com/",
    "http://good.com\\evil.com/",
    "HTTP://EXAMPLE.COM/",
    "http://sub.good.com\\@good.com/",
    "http://good.com/%2e%2e/evil.com",
    "http://good.com?@127.0.0.1/",
]


def _sample(rng: random.Random) -> list[str]:
    out: list[str] = []
    for host in HOSTS:
        for template in TEMPLATES:
            out.append(template.format(h=host))
    # additional seeded mutations on random ports/paths/userinfo
    labels = ["a", "b", "prod", "www", "cdn", "api", "static"]
    for _ in range(600):
        host = rng.choice(HOSTS)
        scheme = rng.choice(["http", "https", "HTTP", "ftp"])
        port = rng.choice(["", ":80", ":443", ":8080", ":0", ":65535", ":99999"])
        path = rng.choice(["/", "/a/b", "/path?q=1", "/#frag", "/%2e%2e/", "//x"])
        user = rng.choice(["", "u@", "www.data@", "a.b@"])
        prefix = rng.choice(["", "//", "///", "////"])
        dot = rng.choice(["", ".", "\\", "%2e"])
        label = rng.choice(labels)
        raw = f"{scheme}:{prefix}{user}{host}{dot}{label}{port}{path}"
        out.append(raw)
    return out


def build_corpus() -> dict:
    rng = random.Random(SEED)
    raw = list(CURATED) + _sample(rng)
    seen: dict[str, int] = {}
    unique: list[str] = []
    for url in raw:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        if digest in seen:
            seen[digest] += 1
            continue
        seen[digest] = 1
        unique.append(url)
    index = {hashlib.sha256(u.encode("utf-8")).hexdigest(): u for u in unique}
    corpus_sha = hashlib.sha256(
        json.dumps(sorted(index), separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "seed": SEED,
        "raw": len(raw),
        "unique": len(unique),
        "duplicates": len(raw) - len(unique),
        "corpus_sha256": corpus_sha,
        "urls": unique,
    }


if __name__ == "__main__":
    corpus = build_corpus()
    print(json.dumps({k: v for k, v in corpus.items() if k != "urls"}, indent=2))