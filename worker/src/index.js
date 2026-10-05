export default {
  async fetch(request, env) {
    if (!env.TUNNEL_URL) {
      return new Response("Cloudflare Tunnel is not configured.", { status: 503 });
    }

    const incoming = new URL(request.url);
    const origin = new URL(env.TUNNEL_URL);
    origin.pathname = incoming.pathname;
    origin.search = incoming.search;

    const headers = new Headers(request.headers);
    if (env.WORKER_SECRET) {
      headers.set("X-Worker-Secret", env.WORKER_SECRET);
    }

    return fetch(new Request(origin, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
      redirect: "follow",
    }));
  },
};
