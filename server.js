require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const db = new Database(path.join(__dirname, 'inbox.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS conversations (
 id TEXT PRIMARY KEY, platform TEXT NOT NULL, customer_id TEXT NOT NULL,
 customer_name TEXT, last_message TEXT, last_at TEXT, unread INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, platform TEXT NOT NULL,
 direction TEXT NOT NULL, body TEXT, created_at TEXT NOT NULL, sender_name TEXT,
 status TEXT DEFAULT 'received'
);
`);
const upsertConversation = db.prepare(`INSERT INTO conversations(id,platform,customer_id,customer_name,last_message,last_at,unread)
VALUES(@id,@platform,@customer_id,@customer_name,@last_message,@last_at,@unread)
ON CONFLICT(id) DO UPDATE SET customer_name=COALESCE(excluded.customer_name,conversations.customer_name),
last_message=excluded.last_message,last_at=excluded.last_at,unread=conversations.unread+excluded.unread`);
const insertMessage = db.prepare(`INSERT OR IGNORE INTO messages(id,conversation_id,platform,direction,body,created_at,sender_name,status)
VALUES(@id,@conversation_id,@platform,@direction,@body,@created_at,@sender_name,@status)`);

function requiredEnv(name) { const v=process.env[name]; if(!v) throw new Error(`Missing server configuration: ${name}`); return v; }
function basicAuth(req,res,next) {
  const header=req.headers.authorization||'';
  if(!header.startsWith('Basic ')){res.set('WWW-Authenticate','Basic realm="Crispy Town Inbox"');return res.status(401).end('Authentication required');}
  let pair=''; try { pair=Buffer.from(header.slice(6),'base64').toString(); } catch {}
  const i=pair.indexOf(':'); const user=pair.slice(0,i), pass=pair.slice(i+1);
  const goodUser=process.env.INBOX_USER||'', goodPass=process.env.INBOX_PASSWORD||'';
  const safe=(a,b)=>a.length===b.length && crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
  if(!goodUser||!goodPass||!safe(user,goodUser)||!safe(pass,goodPass)) return res.status(401).end('Invalid credentials');
  next();
}
app.use(express.json({limit:'1mb', verify:(req,res,buf)=>{ if(req.originalUrl.startsWith('/webhooks/meta')) req.rawBody=Buffer.from(buf); }}));
app.use('/api', basicAuth);

app.get('/webhooks/meta', (req,res)=>{
  const mode=req.query['hub.mode'], token=req.query['hub.verify_token'], challenge=req.query['hub.challenge'];
  if(mode==='subscribe' && token && token===process.env.META_VERIFY_TOKEN) return res.status(200).send(challenge);
  return res.sendStatus(403);
});
function validMetaSignature(req) {
  const secret=process.env.META_APP_SECRET; if(!secret) return false;
  const signature=req.get('x-hub-signature-256')||'';
  if(!signature.startsWith('sha256=')) return false;
  const expected='sha256='+crypto.createHmac('sha256',secret).update(req.rawBody||Buffer.from(JSON.stringify(req.body))).digest('hex');
  const a=Buffer.from(signature), b=Buffer.from(expected);
  return a.length===b.length && crypto.timingSafeEqual(a,b);
}
function saveInbound({platform,customerId,customerName,text,id,at}) {
  const conversationId=`${platform}:${customerId}`; const createdAt=at||new Date().toISOString();
  const messageId=String(id||`${conversationId}:${createdAt}:${crypto.randomUUID()}`);
  upsertConversation.run({id:conversationId,platform,customer_id:String(customerId),customer_name:customerName||null,last_message:text||'[رسالة بدون نص]',last_at:createdAt,unread:1});
  insertMessage.run({id:messageId,conversation_id:conversationId,platform,direction:'in',body:text||'[محتوى غير نصي]',created_at:createdAt,sender_name:customerName||null,status:'received'});
}
app.post('/webhooks/meta',(req,res)=>{
  if(!validMetaSignature(req)) return res.sendStatus(401);
  try {
    const body=req.body||{};
    if(body.object==='whatsapp_business_account') {
      for(const entry of body.entry||[]) for(const change of entry.changes||[]) {
        if(change.field!=='messages') continue;
        const v=change.value||{}; const contacts=v.contacts||[]; const names=new Map(contacts.map(c=>[c.wa_id,c.profile&&c.profile.name]));
        for(const m of v.messages||[]) saveInbound({platform:'whatsapp',customerId:m.from,customerName:names.get(m.from),text:m.text?.body||`[${m.type||'media'}]`,id:m.id,at:m.timestamp?new Date(Number(m.timestamp)*1000).toISOString():undefined});
      }
    } else if(body.object==='page' || body.object==='instagram') {
      const platform=body.object==='instagram'?'instagram':'facebook';
      for(const entry of body.entry||[]) for(const event of entry.messaging||[]) {
        if(event.message && !event.message.is_echo && event.sender?.id) saveInbound({platform,customerId:event.sender.id,text:event.message.text||'[محتوى غير نصي]',id:event.message.mid,at:event.timestamp?new Date(Number(event.timestamp)).toISOString():undefined});
      }
    }
    res.sendStatus(200);
  } catch(err) { console.error('Webhook processing error',err); res.sendStatus(500); }
});

app.get('/api/status',(req,res)=>res.json({ok:true,configured:{facebook:!!(process.env.FACEBOOK_PAGE_ID&&process.env.FACEBOOK_PAGE_ACCESS_TOKEN),instagram:!!(process.env.INSTAGRAM_ACCOUNT_ID&&process.env.INSTAGRAM_PAGE_ACCESS_TOKEN),whatsapp:!!(process.env.WHATSAPP_PHONE_NUMBER_ID&&process.env.WHATSAPP_ACCESS_TOKEN)},webhook:'/webhooks/meta'}));
app.get('/api/conversations',(req,res)=>{
 const rows=db.prepare('SELECT * FROM conversations ORDER BY last_at DESC LIMIT 300').all();
 res.json(rows);
});
app.get('/api/conversations/:id/messages',(req,res)=>{
 const rows=db.prepare('SELECT * FROM messages WHERE conversation_id=? ORDER BY created_at ASC LIMIT 500').all(req.params.id);
 db.prepare('UPDATE conversations SET unread=0 WHERE id=?').run(req.params.id);
 res.json(rows);
});
app.post('/api/send',async(req,res)=>{
 try {
  const {conversationId,text,operator}=req.body||{};
  if(!conversationId||!text?.trim()) return res.status(400).json({error:'conversationId and text are required'});
  const c=db.prepare('SELECT * FROM conversations WHERE id=?').get(conversationId);
  if(!c) return res.status(404).json({error:'Conversation not found'});
  const version=requiredEnv('GRAPH_API_VERSION'); let url, token, payload;
  if(c.platform==='whatsapp') {
    token=requiredEnv('WHATSAPP_ACCESS_TOKEN'); const phoneId=requiredEnv('WHATSAPP_PHONE_NUMBER_ID');
    url=`https://graph.facebook.com/${version}/${phoneId}/messages`;
    payload={messaging_product:'whatsapp',recipient_type:'individual',to:c.customer_id,type:'text',text:{preview_url:false,body:text.trim()}};
  } else if(c.platform==='facebook') {
    token=requiredEnv('FACEBOOK_PAGE_ACCESS_TOKEN'); const pageId=requiredEnv('FACEBOOK_PAGE_ID');
    url=`https://graph.facebook.com/${version}/${pageId}/messages`;
    payload={recipient:{id:c.customer_id},messaging_type:'RESPONSE',message:{text:text.trim()}};
  } else if(c.platform==='instagram') {
    token=requiredEnv('INSTAGRAM_PAGE_ACCESS_TOKEN'); const accountId=requiredEnv('INSTAGRAM_ACCOUNT_ID');
    url=`https://graph.facebook.com/${version}/${accountId}/messages`;
    payload={recipient:{id:c.customer_id},message:{text:text.trim()}};
  } else return res.status(400).json({error:'Unsupported platform'});
  const response=await fetch(url,{method:'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const result=await response.json();
  if(!response.ok) return res.status(response.status).json({error:'Meta send failed',details:result});
  const createdAt=new Date().toISOString(); const messageId=result.message_id||result.messages?.[0]?.id||crypto.randomUUID();
  insertMessage.run({id:String(messageId),conversation_id:conversationId,platform:c.platform,direction:'out',body:text.trim(),created_at:createdAt,sender_name:operator||'موظف',status:'sent'});
  upsertConversation.run({id:conversationId,platform:c.platform,customer_id:c.customer_id,customer_name:c.customer_name,last_message:text.trim(),last_at:createdAt,unread:0});
  res.json({ok:true,id:messageId});
 } catch(err) { console.error(err); res.status(500).json({error:err.message||'Send failed'}); }
});
app.use(express.static(path.join(__dirname,'..')));
const port=Number(process.env.PORT||3000);
app.listen(port,()=>console.log(`Crispy Town inbox listening on :${port}`));
