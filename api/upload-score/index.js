const crypto = require("crypto");
const { Readable } = require("stream");
const Busboy = require("busboy");
const { BlobServiceClient } = require("@azure/storage-blob");

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type",
  "access-control-allow-methods": "POST, OPTIONS"
};

const json = (status, body) => ({
  status,
  headers: { ...corsHeaders, "content-type": "application/json; charset=utf-8" },
  body: JSON.stringify(body)
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
    context.res = { status: 204, headers: corsHeaders };
    return;
  }

  const tokenSecret = process.env.TOKEN_SECRET || "";
  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING || "";
  if (!tokenSecret || !conn) {
    context.res = json(500, { ok: false, error: "missing env TOKEN_SECRET/AZURE_STORAGE_CONNECTION_STRING" });
    return;
  }

  const auth = req.headers?.authorization || req.headers?.Authorization || "";
  const m = String(auth).match(/^Bearer\s+(.+)$/i);
  if (!m) {
    context.res = json(401, { ok: false, error: "missing bearer token" });
    return;
  }

  const vr = verifyJwtHs256(m[1], tokenSecret);
  if (!vr.ok) {
    context.res = json(401, { ok: false, error: vr.error });
    return;
  }

  const contentType = req.headers["content-type"] || req.headers["Content-Type"] || "";
  if (!String(contentType).includes("multipart/form-data")) {
    context.res = json(400, { ok: false, error: "expected multipart/form-data" });
    return;
  }

  const raw = req.rawBody || req.body;
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw || "");
  const stream = Readable.from(buf);

  let matchId = "";
  let fileBuf = null;
  let fileType = "image/png";

  const bb = Busboy({ headers: { "content-type": contentType } });

  const filePromise = new Promise((resolve, reject) => {
    bb.on("field", (name, val) => {
      if (name === "matchId") matchId = safe(val, 40);
    });

    bb.on("file", (name, file, info) => {
      if (name !== "image") {
        file.resume();
        return;
      }
      fileType = info?.mimeType || "image/png";
      const chunks = [];
      file.on("data", (d) => chunks.push(d));
      file.on("end", () => {
        fileBuf = Buffer.concat(chunks);
      });
    });

    bb.on("error", reject);
    bb.on("finish", resolve);
  });

  stream.pipe(bb);
  await filePromise;

  if (!matchId) {
    context.res = json(400, { ok: false, error: "missing matchId" });
    return;
  }
  if (!fileBuf || !fileBuf.length) {
    context.res = json(400, { ok: false, error: "missing image" });
    return;
  }

  const containerName = "scoreboards";
  const blobPath = `${matchId}/score.png`;

  const blobService = BlobServiceClient.fromConnectionString(conn);
  const container = blobService.getContainerClient(containerName);
  const blockBlob = container.getBlockBlobClient(blobPath);

  await blockBlob.uploadData(fileBuf, {
    blobHTTPHeaders: { blobContentType: fileType || "image/png" }
  });

  context.res = json(200, { ok: true, matchId, blobPath });
};
