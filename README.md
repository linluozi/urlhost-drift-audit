# urlhost-drift-audit

**Which host does a URL really point at?** This repo measures where three Python
URL parsers and the browser/WHATWG parser disagree, and turns the disagreement
into concrete SSRF allow-list / deny-list bypass witnesses. It is a deterministic
audit, not a benchmark: every number below was produced by the committed code on
a fixed 1,477-URL corpus, and the whole report is reproducible from a sha256.

Upstream: none

## 这是什么

Python apps routinely *validate* a URL with `urllib.parse.urlsplit` (or `yarl`)
and then *connect* with `requests`/`urllib3` (or a browser follows the redirect).
If the two disagree about the host, the allow-list check and the actual
connection are talking about different machines. This tool extracts the host
with four parsers:

| parser | role in real code |
| --- | --- |
| `urllib.parse.urlsplit` (CPython 3.12.3) | the parser people reach for first |
| `urllib3.util.parse_url` (2.8.0) | what `requests` effectively uses |
| `yarl.URL` (1.25.1) | what `aiohttp` uses |
| Node 24 `new URL()` (WHATWG URL Standard) | the browser / redirect reference |

and classifies every URL as `agree`, `representation_only` (same host, different
spelling), `semantic_divergence` (a different machine), or an accept/reject
mismatch.

## 头条结论

Corpus: 1,505 generated URLs → **1,477 sha256-unique** inputs (28 duplicates
removed), seed `20261117`, corpus sha256 `2c7df605b8b7a326…`.

| parser | agree | semantic divergence | representation only | accepts, reference rejects | rejects, reference accepts |
| --- | --- | --- | --- | --- | --- |
| stdlib | 320 | **816** | 57 | 249 | 17 |
| urllib3 | 433 | **547** | 70 | 147 | 160 |
| yarl | 368 | **572** | 56 | 174 | 214 |

Two practical policies were then run on the same corpus. Both are the naive
string comparisons that appear in real filter code:

| policy | stdlib | urllib3 | yarl |
| --- | --- | --- | --- |
| allow-list `{good.com, sub.good.com, example.com}`, browser target | **7** | 0 | 0 |
| allow-list, same-predicate `urllib3` client target | **7** | 0 | **6** |
| deny-list of loopback *strings* `{127.0.0.1, localhost, ::1, [::1], 0.0.0.0}` | **244** | **210** | **193** |
| …of which survive a correct canonicaliser (`canon_defeated`) | 216 | 177 | 179 |

The most important single witness:

```
http://evil.com\@good.com/
  stdlib  hostname -> good.com     <- allow-list sees a trusted host
  urllib3 host     -> evil.com     <- the HTTP client connects to evil.com
  node    hostname -> evil.com     <- the browser also goes to evil.com
```

WHATWG promotes `\` to `/` for special schemes, so `evil.com` is the host and
`\@good.com` is path; `urlsplit` instead treats the last `@` as the userinfo
separator and reports `good.com`. A validator using `urlsplit` and a client
using `urllib3`/`requests` therefore disagree by construction — all 7
allow-list witnesses are backslash URLs.

The second family is IPv4 alternate notation. The browser canonicalises
`0177.0.0.1`, `2130706433`, `0x7f.1`, `127.1`, `0`, `0300.0250.0001.0001` and
`%31%32%37.0.0.1` to a real address; none of the three Python parsers do. A
loopback deny-list that compares the parser's string never sees `127.0.0.1`
(216 of the 244 stdlib misses are not fixed even if you canonicalise what the
Python parser returned). Third family: three Unicode dot characters
(`。．｡`) are folded to `.` by WHATWG and by `yarl`, but `urllib3` keeps them
literal — the reverse direction of the same bug.

## 独立复核（不依赖 Node 的结果）

`urlhostdrift/ipv4_whatwg.py` re-implements the WHATWG IPv4 parser from the
spec (hex/octal/decimal parts, short forms, trailing dot, percent-decoding).
`verify_ipv4_oracle` replays it over every corpus URL whose authority is an
unambiguous numeric token and compares it to the Node reference:

```
ipv4 oracle: checked=154 mismatches=0
```

So the IPv4 part of the reference is confirmed by an independent implementation,
not taken on trust.

## 怎么跑

```bash
python3 -m venv .venv && .venv/bin/pip install urllib3 yarl
.venv/bin/python -m urlhostdrift run --out evidence      # writes evidence/summary.json
.venv/bin/python -m unittest discover -s tests -t . -v   # 19 tests, OK
```

`node` (>= 18) must be on `PATH`; `node --version` here is `v24.19.0`.
`python -m urlhostdrift show` prints the committed digest, and
`python -m urlhostdrift selftest` runs the audit twice and compares the
`report_sha256` (this is assertion #1 of the test suite).

## 证据与可复现性

* `evidence/summary.json` — full report, `report_sha256 =
  e0df05396034f071b2660214e7e81d09d6a32a55210f5f2c95f79a6fe09d2db7`
  (canonical JSON of everything except the digest itself).
* `evidence/findings.json` — every class count, every guard and every witness.
* The digest is stable across runs; `tests/test_diff.py` re-runs the audit
  twice and also asserts the committed file equals a fresh run byte-for-byte in
  its classified counts and guard blocks. Re-running does not need the network.
* Raw samples are the corpus itself: `urlhostdrift/corpus.py` regenerates the
  exact 1,477 URLs from seed `20261117` (no data file to drift).

## 环境

* CPU AMD EPYC 7K62 (4 vCPU), 3723 MB RAM, CPython 3.12.3, urllib3 2.8.0,
  yarl 1.25.1, Node v24.19.0.
* No timing is measured, so there is no warmup/noise budget and no speedup is
  claimed. Every figure above is a count over a fixed input set.

## 本轮创新

**新在哪**：第一次把「Python URL 解析器 vs WHATWG 主机语义」做成**可判定的中
间人差集**，把 `semantic_divergence`（真的连到另一台机器）与
`representation_only`（同一台机器的不同拼法）分开计数，并把结论落成两条真实
过滤器策略的绕过见证（allow-list vs 浏览器/urllib3 客户端；loopback 字符串
deny-list）。和台账里的 `gitignore-oracle`（.gitignore 判定溯源）与
`perfdrift-ident`（性能归因零空间）不同：这里被测对象是**同一个 URL 在四个解
析器下的主机身份**，且给出的是允许/拒绝策略的反例，而不是某个库的单点优化。

**为什么能推翻旧假设**：常见约定「`urlsplit` 的主机名就是浏览器的主机名」在
本语料上错 816 次；「拒绝 `127.0.0.1` 字符串就够了」在 216 个 URL 上错（且即
使对 Python 输出做 IP 规范化也仍然漏）。两条都能用 README 里的命令当场复现，
不需要网络、不需要上游代码。

## 边界（诚实声明）

* The reference is Node's `URL`; the browser is assumed to behave like WHATWG.
  The IPv4 subset of that reference is independently confirmed (154/154).
* A witness shows the two parsers return different hosts. It does **not** claim
  a specific production app is exploitable; it shows the shape of the bug and
  names the parser pair. Whether the request is actually sent depends on which
  library the app uses for each step.
* `representation_only` differences are counted separately and are not reported
  as bypasses.
* Unambiguous scope: only the host is compared, not path, query or cookies.

## License

MIT (original work; no upstream code is copied or executed). See `LICENSE`.
