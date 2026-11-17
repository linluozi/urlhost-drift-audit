// WHATWG URL reference.  Reads a JSON array of URL strings on stdin and writes
// one JSON object per input: {ok, host, scheme, port, error?}.
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const out = input.map((raw) => {
  try {
    const u = new URL(raw);
    return {
      ok: true,
      host: u.hostname === "" ? null : u.hostname,
      scheme: u.protocol.replace(/:$/, ""),
      port: u.port === "" ? null : Number(u.port),
    };
  } catch (err) {
    return { ok: false, error: "TypeError" };
  }
});
process.stdout.write(JSON.stringify(out));