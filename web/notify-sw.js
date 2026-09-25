self.addEventListener("message", (ev) => {
  const d = ev.data || {};
  if (d.type !== "sc5-notify") return;
  const title = String(d.title || "SquidC5");
  const body = String(d.body || "");
  const tag = String(d.tag || "sc5");
  ev.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag,
      renotify: true,
      icon: "/ops/assets/squidsec-logo-96.png",
    })
  );
});

self.addEventListener("notificationclick", (ev) => {
  ev.notification.close();
  ev.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      if (list.length) return list[0].focus();
      return self.clients.openWindow("/ops");
    })
  );
});
