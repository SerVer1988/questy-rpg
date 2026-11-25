const APP_URL='https://server1988.github.io/questy-rpg/';
self.addEventListener('install',event=>{self.skipWaiting()});
self.addEventListener('activate',event=>{event.waitUntil(self.clients.claim())});
self.addEventListener('push',event=>{
  let data={};try{data=event.data?event.data.json():{}}catch(e){data={body:event.data?.text()||''}}
  const title=data.title||'Фокси зовёт! 🦊';
  const options={body:data.body||'Загляни в Questy — у нас новое приключение.',icon:'./icon.svg',badge:'./icon.svg',tag:data.tag||'questy-reminder',renotify:false,data:{url:data.url||APP_URL},vibrate:[120,60,120]};
  event.waitUntil(self.registration.showNotification(title,options));
});
self.addEventListener('notificationclick',event=>{
  event.notification.close();
  const target=event.notification.data?.url||APP_URL;
  event.waitUntil((async()=>{
    const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});
    for(const client of windows){if('focus' in client){await client.focus();if('navigate' in client)await client.navigate(target);return;}}
    if(self.clients.openWindow)await self.clients.openWindow(target);
  })());
});
