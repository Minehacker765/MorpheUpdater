export default {
  async fetch(request) {
    const url = new URL(request.url);
    let path = url.pathname.replace(/^\//, "");
    if (path === "") path = "index-v1.json";

    // APKs live only as release assets — redirect to latest
    if (path.endsWith(".apk") || path.endsWith(".idsig")) {
      const name = path.split("/").pop();
      return Response.redirect(
        `https://github.com/Minehacker765/MorpheUpdater/releases/latest/download/${name}`,
        302
      );
    }

    // index + icons/branding are committed (small) — proxy from raw
    // icons/ and branding/ are at repo root (new), out/* is F-Droid repo (legacy)
    const bases = [
      "https://raw.githubusercontent.com/Minehacker765/MorpheUpdater/main/out",
      "https://raw.githubusercontent.com/Minehacker765/MorpheUpdater/main",
      "https://minehacker765.github.io/MorpheUpdater",
    ];
    for (const base of bases) {
      const r = await fetch(`${base}/${path}`);
      if (r.ok) {
        const h = new Headers(r.headers);
        h.set("Access-Control-Allow-Origin", "*");
        h.set("Cache-Control", "public, max-age=300");
        return new Response(r.body, { status: r.status, headers: h });
      }
    }
    return new Response("Not found", { status: 404 });
  },
};
