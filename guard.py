"""Minimal auth wrapper: serves the MCP endpoint under a secret path segment."""

import hmac
import os

import httpx
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Route

SECRET = os.environ["MCP_SECRET_PATH"]
UPSTREAM = os.environ.get("MCP_UPSTREAM", "http://127.0.0.1:8000/mcp")

# Hop-by-hop headers plus ones uvicorn regenerates, to avoid duplicates.
DROP = {
    "host", "content-length", "transfer-encoding", "connection", "keep-alive",
    "date", "server",
}

client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))


async def healthz(_request):
    return PlainTextResponse("ok")


async def proxy(request):
    if not hmac.compare_digest(request.path_params["secret"], SECRET):
        return PlainTextResponse("Not Found", status_code=404)

    headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP}
    upstream_req = client.build_request(
        request.method, UPSTREAM, headers=headers, content=await request.body()
    )
    try:
        upstream = await client.send(upstream_req, stream=True)
    except httpx.ConnectError:
        return PlainTextResponse("MCP server not ready", status_code=503)

    return StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers={k: v for k, v in upstream.headers.items() if k.lower() not in DROP},
        background=BackgroundTask(upstream.aclose),
    )


app = Starlette(routes=[
    Route("/healthz", healthz),
    Route("/{secret}/mcp", proxy, methods=["GET", "POST", "DELETE"]),
])
