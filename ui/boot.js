// The page Magpie serves is a shutter: its frame cannot reach the network
// (connect-src 'none'). The plugin's host runs the real UI on loopback,
// declared as magpie.page.service. In the desktop window 127.0.0.1 is this
// computer; in magpie web the bridge hands us Magpie's own proxy address.
// Navigating the frame is not a fetch, so the shutter may open it.
(async () => {
  const label = document.getElementById("abBoot");
  try {
    // Scripts run, so this file can take the page to the service: the
    // refresh index.html carries is for a window that runs none of the
    // page folder's scripts, and must not fire here (it would take a
    // browser that opened the page through magpie web off magpie's proxy).
    document.querySelector('meta[http-equiv="refresh"]')?.remove();
    // A window that runs this file but not the bridge still has to be
    // handled: magpie is undefined then, and magpie web's proxy address
    // can't be read, so the service's own address is used.
    if (!window.magpie) {
      label.textContent = "正在打开账号备份…";
      location.replace("http://127.0.0.1:39872/app.html");
      return;
    }
    await magpie.ready;
    let port = 39872;
    try {
      const opts = await magpie.options.get();
      const p = Number(opts && opts.port);
      if (Number.isInteger(p) && p >= 1 && p <= 65535) port = p;
    } catch { /* no option set: the package's port */ }
    const svc = String(magpie.service || "").trim();
    const root = svc ? (svc.endsWith("/") ? svc : svc + "/") : `http://127.0.0.1:${port}/`;
    label.textContent = "正在打开账号备份…";
    location.replace(new URL("app.html", root).href);
  } catch (err) {
    label.textContent = "账号备份没能启动：" + String((err && err.message) || err);
  }
})();
