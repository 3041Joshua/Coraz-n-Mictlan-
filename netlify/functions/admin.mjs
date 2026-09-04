import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const store = getStore({ name: 'corazon-mictlan', consistency: 'strong' });
const cookieName = 'cm_admin';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
}
function token() {
  const secret = process.env.ADMIN_PASSWORD;
  if (!secret) throw new Error('Falta configurar ADMIN_PASSWORD en Netlify.');
  const exp = Date.now() + 1000 * 60 * 60 * 12;
  const raw = `admin.${exp}`;
  const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  return `${raw}.${sig}`;
}
function validToken(req) {
  const secret = process.env.ADMIN_PASSWORD;
  const c = req.headers.get('cookie') || '';
  const value = c.split(';').map(x => x.trim()).find(x => x.startsWith(cookieName + '='))?.split('=')[1];
  if (!secret || !value) return false;
  const [kind, exp, sig] = value.split('.');
  if (kind !== 'admin' || !exp || !sig || Number(exp) < Date.now()) return false;
  const expected = crypto.createHmac('sha256', secret).update(`admin.${exp}`).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
async function getContent() {
  return (await store.get('content.json', { type: 'json' })) || { events: [], cards: [] };
}

export default async (req) => {
  try {
    const url = new URL(req.url);
    const action = url.searchParams.get('action');

    if (req.method === 'POST' && action === 'login') {
      const body = await req.json();
      if (!process.env.ADMIN_PASSWORD || body.password !== process.env.ADMIN_PASSWORD) return json({ ok: false, error: 'Contraseña incorrecta.' }, 401);
      return json({ ok: true }, 200, { 'set-cookie': `${cookieName}=${token()}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200` });
    }

    if (req.method === 'POST' && action === 'logout') {
      return json({ ok: true }, 200, { 'set-cookie': `${cookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0` });
    }

    if (req.method === 'GET' && action === 'image') {
      const key = url.searchParams.get('key');
      if (!key || !key.startsWith('images/')) return new Response('Not found', { status: 404 });
      const result = await store.getWithMetadata(key, { type: 'arrayBuffer' });
      if (!result) return new Response('Not found', { status: 404 });
      return new Response(result.data, { headers: { 'content-type': result.metadata?.contentType || 'application/octet-stream', 'cache-control': 'public, max-age=31536000, immutable' } });
    }

    if (req.method === 'GET') return json({ ok: true, ...(await getContent()) });

    if (!validToken(req)) return json({ ok: false, error: 'No autorizado.' }, 401);

    if (req.method === 'POST' && action === 'save') {
      const form = await req.formData();
      const type = form.get('type');
      const id = form.get('id') || crypto.randomUUID();
      const content = await getContent();
      const item = JSON.parse(form.get('data'));
      const file = form.get('image');

      if (file && typeof file.arrayBuffer === 'function' && file.size > 0) {
        const ext = (file.type?.split('/')[1] || 'jpg').replace('jpeg', 'jpg');
        const key = `images/${type}-${id}.${ext}`;
        await store.set(key, Buffer.from(await file.arrayBuffer()), { metadata: { contentType: file.type || 'image/jpeg' } });
        item.image = `/.netlify/functions/admin?action=image&key=${encodeURIComponent(key)}`;
      }

      const list = type === 'event' ? content.events : content.cards;
      const index = list.findIndex(x => x.id === id);
      if (index >= 0) list[index] = { ...list[index], ...item, id };
      else list.push({ ...item, id });
      await store.setJSON('content.json', content);
      return json({ ok: true, item: list.find(x => x.id === id), ...content });
    }

    if (req.method === 'POST' && action === 'delete') {
      const body = await req.json();
      const content = await getContent();
      const list = body.type === 'event' ? content.events : content.cards;
      const index = list.findIndex(x => x.id === body.id);
      if (index >= 0) list.splice(index, 1);
      await store.setJSON('content.json', content);
      return json({ ok: true, ...content });
    }

    return json({ ok: false, error: 'Acción no válida.' }, 400);
  } catch (e) {
    return json({ ok: false, error: e.message || 'Error del servidor.' }, 500);
  }
};
