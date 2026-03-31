const { BlobServiceClient } = require("@azure/storage-blob");

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "GET, OPTIONS"
};

const safe = (s, max) => String(s || "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, max);

module.exports = async function (context, req) {
  if (req.method === "OPTIONS") {
    context.res = { status: 204, headers: corsHeaders };
    return;
  }

  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING || "";
  if (!conn) {
    context.res = {
      status: 500,
      headers: { ...corsHeaders, "content-type": "text/plain; charset=utf-8" },
      body: "missing env AZURE_STORAGE_CONNECTION_STRING"
    };
    return;
  }

  const matchId = safe(req.query?.matchId, 40);
  if (!matchId) {
    context.res = {
      status: 400,
      headers: { ...corsHeaders, "content-type": "text/plain; charset=utf-8" },
      body: "missing matchId"
    };
    return;
  }

  const containerName = "scoreboards";
  const blobPath = `${matchId}/score.png`;

  try {
    const blobService = BlobServiceClient.fromConnectionString(conn);
    const container = blobService.getContainerClient(containerName);
    const blob = container.getBlobClient(blobPath);

    const dl = await blob.download();
    const ct = dl.contentType || "image/png";

    context.res = {
      status: 200,
      isRaw: true,
      headers: {
        ...corsHeaders,
        "content-type": ct,
        "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
        "pragma": "no-cache",
        "expires": "0"
      },
      body: await streamToBuffer(dl.readableStreamBody)
    };
  } catch (e) {
    context.res = {
      status: 404,
      headers: { ...corsHeaders, "content-type": "text/plain; charset=utf-8" },
      body: "not found"
    };
  }
};

async function streamToBuffer(readableStream) {
  if (!readableStream) return Buffer.from([]);
  return new Promise((resolve, reject) => {
    const chunks = [];
    readableStream.on("data", (d) => chunks.push(Buffer.from(d)));
    readableStream.on("end", () => resolve(Buffer.concat(chunks)));
    readableStream.on("error", reject);
  });
}
