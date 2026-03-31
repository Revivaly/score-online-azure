const {
  BlobServiceClient,
  StorageSharedKeyCredential,
  generateBlobSASQueryParameters,
  BlobSASPermissions,
} = require("@azure/storage-blob");

const corsHeaders = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type",
  "access-control-allow-methods": "GET, OPTIONS",
};

const safe = (s, max) => String(s || "").replace(/[^a-zA-Z0-9_-]+/g, "_").slice(0, max);

const getConnValue = (conn, key) => {
  const m = String(conn).match(new RegExp(`${key}=([^;]+)`, "i"));
  return m ? m[1] : "";
};

module.exports = async function (context, req) {
  if (req.method === "OPTIONS") {
    context.res = { status: 204, headers: corsHeaders };
    return;
  }

  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING || "";
  if (!conn) {
    context.res = { status: 500, headers: corsHeaders, body: "missing AZURE_STORAGE_CONNECTION_STRING" };
    return;
  }

  const matchId = safe(req.query?.matchId, 40);
  if (!matchId) {
    context.res = { status: 400, headers: corsHeaders, body: "missing matchId" };
    return;
  }

  const accountName = getConnValue(conn, "AccountName");
  const accountKey = getConnValue(conn, "AccountKey");
  if (!accountName || !accountKey) {
    context.res = { status: 500, headers: corsHeaders, body: "missing AccountName/AccountKey in connection string" };
    return;
  }

  const containerName = "scoreboards";
  const blobPath = `${matchId}/score.png`;

  const blobService = BlobServiceClient.fromConnectionString(conn);
  const container = blobService.getContainerClient(containerName);
  const blobClient = container.getBlobClient(blobPath);

  // (Opcional) si quieres 404 limpio cuando no existe:
  const exists = await blobClient.exists();
  if (!exists) {
    context.res = { status: 404, headers: corsHeaders, body: "not found" };
    return;
  }

  const credential = new StorageSharedKeyCredential(accountName, accountKey);
  const expiresOn = new Date(Date.now() + 10 * 60 * 1000); // 10 min

  const sas = generateBlobSASQueryParameters(
    {
      containerName,
      blobName: blobPath,
      permissions: BlobSASPermissions.parse("r"),
      expiresOn,
    },
    credential
  ).toString();

  const redirectUrl = `${blobClient.url}?${sas}`;

  context.res = {
    status: 302,
    headers: {
      ...corsHeaders,
      Location: redirectUrl,
      "cache-control": "no-store, no-cache, must-revalidate, max-age=0",
      pragma: "no-cache",
      expires: "0",
    },
  };
};
