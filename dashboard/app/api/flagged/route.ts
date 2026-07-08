// Server-side proxy to the Go API. The API key lives only here (never in
// client bundles), attached as X-API-Key on the outgoing request.

const GO_API = process.env.SECUREPAY_API_BASE ?? "http://localhost:8080";

export async function GET() {
  const apiKey = process.env.SECUREPAY_API_KEY;
  if (!apiKey) {
    return Response.json(
      { error: "SECUREPAY_API_KEY is not set on the dashboard server" },
      { status: 500 },
    );
  }

  const res = await fetch(`${GO_API}/api/flagged`, {
    headers: { "X-API-Key": apiKey },
    cache: "no-store",
  });

  return new Response(await res.text(), {
    status: res.status,
    headers: { "Content-Type": "application/json" },
  });
}
