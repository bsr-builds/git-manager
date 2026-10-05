export default {
  async fetch(request, env) {
    try {
      const tunnelUrl = env.TUNNEL_URL;
      if (!tunnelUrl) {
        return new Response("Cloudflare Tunnel is not configured.", { status: 503 });
      }

      const incoming = new URL(request.url);
      const origin = new URL(tunnelUrl);
      origin.pathname = incoming.pathname;
      origin.search = incoming.search;

      const headers = new Headers(request.headers);
      headers.set("Host", origin.host);
      headers.set("X-Forwarded-Host", incoming.host);
      headers.set("X-Forwarded-Proto", incoming.protocol.replace(":", ""));
      headers.delete("content-length");

      if (env.WORKER_SECRET) {
        headers.set("X-Worker-Secret", env.WORKER_SECRET);
      }

      // Read body as ArrayBuffer to prevent stream lock issues on POST redirects
      let body = null;
      if (request.method !== "GET" && request.method !== "HEAD") {
        body = await request.arrayBuffer();
      }

      const init = {
        method: request.method,
        headers,
        body,
        redirect: "manual", // CRITICAL: Do NOT follow redirects internally
      };

      const response = await fetch(origin.toString(), init);

      // Clone response headers to handle redirects and cookies properly
      const responseHeaders = new Headers(response.headers);

      // If backend redirects to internal tunnel URL, rewrite it back to Worker domain
      const location = responseHeaders.get("location");
      if (location) {
        try {
          const locUrl = new URL(location, origin.origin);
          if (locUrl.origin === origin.origin) {
            responseHeaders.set("location", incoming.origin + locUrl.pathname + locUrl.search);
          }
        } catch (e) {
          // relative paths work automatically in browsers
        }
      }

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      console.error("Worker proxy error:", error);
      return new Response("Worker proxy error: " + (error.stack || error.message), { status: 502 });
    }
  },
};
