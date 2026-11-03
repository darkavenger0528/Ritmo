self.addEventListener('fetch', () => {});
self.addEventListener('push', e => {
  const d = e.data ? e.data.json() : { title: 'Ritmo', body: '' };
  e.waitUntil(self.registration.showNotification(d.title, { body: d.body, icon: '/icon-192.png', badge: '/icon-192.png' }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window' }).then(l => l[0] ? l[0].focus() : clients.openWindow('/')));
});
