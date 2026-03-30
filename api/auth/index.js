const crypto = require("crypto");

const json = (status, body) => ({
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "POST, OPTIONS"
  },
  body: JSON.stringify(body)
});

const b64u = (buf) =>
  Buffer.from(buf).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");

const signJwtHs256 = (payload, secret) => {
  const header = { alg: "HS256", typ: "JWT" };
  const head = b64u(JSON.stringify(header));
  const pay = b64u(JSON.stringify(payload));
  const data = `${head}.${pay}`;
  const sig = b64u(crypto.createHmac("sha256", secret).update(data).digest());
  return `${data}.${sig}`;
};

module.exports = async function (context, req) {
  if (req.method === "OPTIONS") {
    context.res = { status: 204, headers: json(204, {}).headers };
    return;
  }

  const adminPin = process.env.ADMIN_PIN || "";
  const tokenSecret = process.env.TOKEN_SECRET || "";
  if (!adminPin || !tokenSecret) {
    context.res = json(500, { ok: false, error: "missing env ADMIN_PIN/TOKEN_SECRET" });
    return;
  }

  const pin = (req.body && req.body.pin) ? String(req.body.pin) : "";
  if (!pin) {
    context.res = json(400, { ok: false, error: "missing pin" });
    return;
  }
  if (pin !== adminPin) {
    context.res = json(401, { ok: false, error: "invalid pin" });
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 12 * 60 * 60; // 12h
  const token = signJwtHs256({ sub: "admin", iat: now, exp }, tokenSecret);

  context.res = json(200, { ok: true, token, exp });
};
