export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // The Worker forwards to the existing Cloudflare Named Tunnel hostname.
    // CLOUDFLARE_ORIGIN_HOST should be only the hostname, e.g.
    // git-manager-origin.example.com
    if (!env.CLOUDFLARE_ORIGIN_HOST) {
      return new Response("CLOUDFLARE_ORIGIN_HOST is not configured.", {
        status: 500,
      });
    }

    url.hostname = env.CLOUDFLARE_ORIGIN_HOST;
    url.protocol = "https:";

    const headers = new Headers(request.headers);

    if (env.WORKER_SECRET) {
      headers.set("X-Worker-Secret", env.WORKER_SECRET);
    }

    return fetch(new Request(url, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD"
        ? undefined
        : request.body,
      redirect: "follow",
    }));
  },
};
