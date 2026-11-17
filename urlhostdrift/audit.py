"""Host-normalization differential audit: Python URL parsers vs WHATWG."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict

from . import corpus as corpus_mod
from .ipv4_whatwg import parse_ipv4
from .parsers import PY_PARSERS, REFERENCE, parse_python, parse_reference, parser_versions

ALLOWLIST = {"good.com", "sub.good.com", "example.com"}
LOOPBACK_STRINGS = {"127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "[0:0:0:0:0:0:0:1]"}
LOOPBACK_CANONS = {"127.0.0.1", "::1", "0.0.0.0"}
_FULLWIDTH_DOTS = ("。", "．", "｡")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_HOST_IN_TEXT = re.compile(r"^(?P<user>.*@)?(?P<host>\[[^\]]*\]|[^:/?#]*)(?::(?P<port>\d*))?")


def canon(host: str | None) -> str | None:
    """Canonical 'which host is actually contacted' form.

    IPv4/IPv6 literals are parsed and canonicalised; DNS names are lowercased
    and a single trailing dot is removed.  Anything that does not parse as an
    address stays a DNS-looking string, which is exactly how a validator treats
    it -- so `0177.0.0.1` stays distinct from `127.0.0.1`.
    """
    if host is None:
        return None
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    for candidate in (text, text[:-1] if text.endswith(".") and len(text) > 1 else text):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    out = text.lower()
    if out.endswith(".") and len(out) > 1:
        out = out[:-1]
    return out


def authority_of(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]


def host_token(url: str) -> str:
    auth = authority_of(url)
    auth = auth.rsplit("@", 1)[-1]
    m = _HOST_IN_TEXT.match(auth)
    if not m:
        return auth
    return m.group("host")


def classify_family(url: str) -> str:
    auth = authority_of(url)
    token = host_token(url)
    if "\\" in url:
        return "backslash"
    if ":////" in url or ":///" in url or auth == "":
        return "extra_slashes_or_empty_host"
    if "%00" in url or "%00" in auth:
        return "nul_in_host"
    if _PCT.search(auth):
        return "percent_encoded_host"
    if any(d in url for d in _FULLWIDTH_DOTS):
        return "unicode_dot"
    if "\t" in url or "\n" in url or " " in url:
        return "control_whitespace"
    if "[" in url:
        return "ipv6_representation"
    parsed = parse_ipv4(token)
    if parsed is not None and parsed != token:
        return "ipv4_alternate_notation"
    if token.endswith(".") and token:
        return "trailing_dot"
    if any(c.isupper() for c in token):
        return "host_case"
    if token == "":
        return "extra_slashes_or_empty_host"
    return "other"


def classify(parsed: dict, ref: dict) -> str:
    if not ref.get("ok", False):
        return "parser_accepts_reference_rejects" if parsed.get("ok") else "both_reject"
    if not parsed.get("ok", False):
        return "parser_rejects_reference_accepts"
    ph, rh = parsed.get("host"), ref.get("host")
    if ph is None and rh is None:
        return "agree"
    if ph is None or rh is None:
        return "semantic_divergence"
    if ph == rh:
        return "agree"
    if canon(ph) == canon(rh):
        return "representation_only"
    return "semantic_divergence"


def audit() -> dict:
    corpus = corpus_mod.build_corpus()
    urls = corpus["urls"]
    refs = parse_reference(urls)
    py = {u: parse_python(u) for u in urls}

    classes: dict[str, Counter] = {name: Counter() for name in PY_PARSERS}
    families: dict[str, Counter] = {name: Counter() for name in PY_PARSERS}
    witnesses: dict[str, list] = defaultdict(list)

    for url in urls:
        ref = refs[url]
        for name in PY_PARSERS:
            parsed = py[url][name]
            klass = classify(parsed, ref)
            classes[name][klass] += 1
            if klass in ("semantic_divergence", "parser_rejects_reference_accepts",
                         "parser_accepts_reference_rejects"):
                fam = classify_family(url)
                families[name][fam] += 1
                if len(witnesses[name]) < 60:
                    witnesses[name].append({
                        "url": url,
                        "class": klass,
                        "family": fam,
                        "parser_host": parsed.get("host"),
                        "reference_host": ref.get("host"),
                        "parser_error": parsed.get("error"),
                    })

    guard = build_guard(urls, py, refs)
    oracle = verify_ipv4_oracle(urls, refs)

    summary = {
        "meta": {
            "parsers": list(PY_PARSERS),
            "reference": REFERENCE,
            "versions": parser_versions(),
            "corpus_seed": corpus["seed"],
            "corpus_raw": corpus["raw"],
            "corpus_unique": corpus["unique"],
            "corpus_duplicates": corpus["duplicates"],
            "corpus_sha256": corpus["corpus_sha256"],
        },
        "classes": {name: dict(sorted(classes[name].items())) for name in PY_PARSERS},
        "families": {name: dict(sorted(families[name].items())) for name in PY_PARSERS},
        "guard": guard,
        "ipv4_oracle": oracle,
        "witnesses": {name: witnesses[name] for name in PY_PARSERS},
    }
    summary["report_sha256"] = hashlib.sha256(
        json.dumps(summary, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return summary


def build_guard(urls: list[str], py: dict, refs: dict) -> dict:
    """Naive-validator bypass counts for the two policies people actually write.

    A bypass is only counted when the two hosts are *semantically* different
    (``canon()`` differs): a case-only or bracket-only difference is not a
    security witness.
    """
    result: dict[str, dict] = {
        "allowlist_vs_client": {},
        "allowlist_vs_browser": {},
        "deny_loopback_strings": {},
    }
    for validator in PY_PARSERS:
        allow_client, allow_browser, deny_browser = [], [], []
        for url in urls:
            v = py[url][validator]
            if not v.get("ok"):
                continue
            vhost = v.get("host")
            if vhost in ALLOWLIST:
                client = py[url]["urllib3"]
                chost = client.get("host") if client.get("ok") else None
                if chost is not None and canon(chost) != canon(vhost):
                    allow_client.append({"url": url, "validator_host": vhost, "client_host": chost})
                ref = refs[url]
                if ref.get("ok") and canon(ref.get("host")) != canon(vhost):
                    allow_browser.append({
                        "url": url,
                        "validator_host": vhost,
                        "browser_host": ref.get("host"),
                    })
            if vhost not in LOOPBACK_STRINGS:
                ref = refs[url]
                if ref.get("ok") and canon(ref.get("host")) in LOOPBACK_CANONS:
                    vcanon = canon(vhost)
                    deny_browser.append({
                        "url": url,
                        "validator_host": vhost,
                        "validator_canon": vcanon,
                        "browser_host": ref.get("host"),
                        "browser_canon": canon(ref.get("host")),
                        # a validator that canonicalised would still escape this one
                        "canon_defeated": vcanon not in LOOPBACK_CANONS,
                    })
        result["allowlist_vs_client"][validator] = {
            "count": len(allow_client), "witnesses": allow_client[:40],
        }
        result["allowlist_vs_browser"][validator] = {
            "count": len(allow_browser), "witnesses": allow_browser[:40],
        }
        result["deny_loopback_strings"][validator] = {
            "count": len(deny_browser),
            "canon_defeated_count": sum(1 for w in deny_browser if w["canon_defeated"]),
            "witnesses": sorted(
                deny_browser, key=lambda w: (not w["canon_defeated"], w["url"])
            )[:500],
        }
    return result


def verify_ipv4_oracle(urls: list[str], refs: dict) -> dict:
    """Cross-check the independent IPv4 parser against the Node reference."""
    checked = 0
    mismatches = []
    for url in urls:
        if "\\" in url:
            # WHATWG promotes backslash to '/', so a regex token is not the host.
            continue
        token = host_token(url)
        parsed = parse_ipv4(token)
        if parsed is None:
            continue
        ref = refs[url]
        if not ref.get("ok"):
            continue
        checked += 1
        ref_host = canon(ref.get("host"))
        if ref_host != parsed:
            mismatches.append({"url": url, "oracle": parsed, "reference": ref.get("host")})
    return {"checked": checked, "mismatches": mismatches[:20], "mismatch_count": len(mismatches)}


def save(summary: dict, outdir) -> dict:
    from pathlib import Path

    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    summary_path = outdir / "summary.json"
    findings_path = outdir / "findings.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    findings = {
        "report_sha256": summary["report_sha256"],
        "classes": summary["classes"],
        "guard": summary["guard"],
        "ipv4_oracle": summary["ipv4_oracle"],
        "witnesses": summary["witnesses"],
    }
    findings_path.write_text(json.dumps(findings, indent=2, sort_keys=True) + "\n")
    return {"summary": str(summary_path), "findings": str(findings_path)}