const crypto = require("crypto");
const { BlobServiceClient } = require("@azure/storage-blob");

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type, x-score-token",
  "access-control-allow-methods": "POST, OPTIONS",
};

const json = (status, body) => ({
  status,
  headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
  body: JSON.stringify(body),
});

const b64uToBuf = (s) => {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(b64, "base64");
};

const verifyJwtHs256 = (token, secret) => {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return { ok: false, error: "bad token format" };

  const [h, p, sig] = parts;
  const data = `${h}.${p}`;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  if (expected !== sig) return { ok: false, error: "bad signature" };

  let payload;
  try {
    payload = JSON.parse(b64uToBuf(p).toString("utf8"));
  } catch {
    return { ok: false, error: "bad payload" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) return { ok: false, error: "token expired" };

  return { ok: true, payload };
};

const safe = (s, max) => String(s || "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, max);

module.exports = async function (context, req) {
  if (req.method === "OPTIONS") {
    context.res = { status: 200, headers: corsHeaders, body: "" };
    return;
  }

  const tokenSecret = process.env.TOKEN_SECRET || "";
  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING || "";
  if (!tokenSecret || !conn) {
    context.res = json(500, { ok: false, error: "missing env TOKEN_SECRET/AZURE_STORAGE_CONNECTION_STRING" });
    return;
  }

  const token =
    (req.headers && (req.headers["x-score-token"] || req.headers["X-Score-Token"])) || "";
  if (!token) {
    context.res = json(401, { ok: false, error: "missing x-score-token" });
    return;
  }

  const vr = verifyJwtHs256(String(token), tokenSecret);
  if (!vr.ok) {
    context.res = json(401, { ok: false, error: vr.error });
    return;
  }

  const ct = String(req.headers["content-type"] || req.headers["Content-Type"] || "");
  if (!ct.toLowerCase().includes("application/json")) {
    context.res = json(415, { ok: false, error: "expected application/json with base64 image" });
    return;
  }

  const matchId = safe(req.body?.matchId, 40);
  let imageBase64 = String(req.body?.imageBase64 || "");

  if (!matchId) {
    context.res = json(400, { ok: false, error: "missing matchId" });
    return;
  }
  if (!imageBase64) {
    context.res = json(400, { ok: false, error: "missing imageBase64" });
    return;
  }

  // allow data URL
  const comma = imageBase64.indexOf(",");
  if (comma >= 0) imageBase64 = imageBase64.slice(comma + 1);

  let bytes;
  try {
    bytes = Buffer.from(imageBase64, "base64");
  } catch {
    context.res = json(400, { ok: false, error: "bad base64" });
    return;
  }

  const containerName = "scoreboards";
  const blobPath = `${matchId}/score.png`;

  const blobService = BlobServiceClient.fromConnectionString(conn);
  const container = blobService.getContainerClient(containerName);
  const blockBlob = container.getBlockBlobClient(blobPath);

  await blockBlob.uploadData(bytes, {
    blobHTTPHeaders: {
      blobContentType: "image/png",
      blobCacheControl: "no-store, no-cache, must-revalidate, max-age=0",
    },
  });

  context.res = json(200, { ok: true, matchId, blobPath });
};
