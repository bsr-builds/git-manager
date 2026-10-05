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
      headers.delete("host");
      headers.delete("content-length");

      if (env.WORKER_SECRET) {
        headers.set("X-Worker-Secret", env.WORKER_SECRET);
      }

      const init = {
        method: request.method,
        headers,
        redirect: "follow",
      };

      if (request.method !== "GET" && request.method !== "HEAD") {
        init.body = request.body;
      }

      return await fetch(origin.toString(), init);
    } catch (error) {
      console.error("Worker proxy error:", error);
      return new Response("Worker proxy error", { status: 502 });
    }
  },
};
