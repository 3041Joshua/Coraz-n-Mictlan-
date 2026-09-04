import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const cookieName = 'cm_admin';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
  });
}

function getSecret() {
  return Netlify.env.get('ADMIN_PASSWORD') || '';
}

function createToken(secret) {
  const exp = Date.now() + 1000 * 60 * 60 * 12;
  const raw = `admin.${exp}`;
  const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  return `${raw}.${sig}`;
}

function readCookie(req) {
  const cookie = req.headers.get('cookie') || '';
  return cookie
    .split(';')
    .map(part => part.trim())
    .find(part => part.startsWith(`${cookieName}=`))
    ?.slice(cookieName.length + 1) || '';
}

function validToken(req, secret) {
  const value = readCookie(req);
  if (!secret || !value) return false;

  const parts = value.split('.');
  if (parts.length !== 3) return false;

  const [kind, exp, sig] = parts;
  if (kind !== 'admin' || !exp || !sig || Number(exp) < Date.now()) return false;

  const expected = crypto.createHmac('sha256', secret).update(`admin.${exp}`).digest('hex');
  const actualBuffer = Buffer.from(sig, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  if (actualBuffer.length !== expectedBuffer.length) return false;

  return crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

async function getContent(store) {
  return (await store.get('content.json', { type: 'json' })) || { events: [], cards: [] };
}

function normalizeContent(content) {
  return {
    events: Array.isArray(content.events) ? content.events : [],
    cards: Array.isArray(content.cards) ? content.cards : []
  };
}

export default async (req) => {
  try {
    const store = getStore({ name: 'corazon-mictlan', consistency: 'strong' });
    const url = new URL(req.url);
    const action = url.searchParams.get('action');
    const secret = getSecret();

    if (req.method === 'POST' && action === 'login') {
      if (!secret) return json({ ok: false, error: 'Falta configurar ADMIN_PASSWORD en Netlify.' }, 500);

      const body = await req.json();
      if (!body?.password || body.password !== secret) {
        return json({ ok: false, error: 'Contraseña incorrecta.' }, 401);
      }

      return json({ ok: true }, 200, {
        'set-cookie': `${cookieName}=${createToken(secret)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`
      });
    }

    if (req.method === 'POST' && action === 'logout') {
      return json({ ok: true }, 200, {
        'set-cookie': `${cookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
      });
    }

    if (req.method === 'GET' && action === 'image') {
      const key = url.searchParams.get('key');
      if (!key || !key.startsWith('images/')) return new Response('Not found', { status: 404 });

      const result = await store.getWithMetadata(key, { type: 'arrayBuffer' });
      if (!result) return new Response('Not found', { status: 404 });

      return new Response(result.data, {
        headers: {
          'content-type': result.metadata?.contentType || 'application/octet-stream',
          'cache-control': 'public, max-age=31536000, immutable'
        }
      });
    }

    if (req.method === 'GET' && action === 'public') {
      const content = normalizeContent(await getContent(store));
      return json({
        ok: true,
        events: content.events.filter(item => item.active !== false),
        cards: content.cards.filter(item => item.active !== false)
      });
    }

    if (req.method === 'GET' && action === 'admin') {
      if (!validToken(req, secret)) return json({ ok: false, error: 'No autorizado.' }, 401);
      return json({ ok: true, ...normalizeContent(await getContent(store)) });
    }

    if (!validToken(req, secret)) return json({ ok: false, error: 'No autorizado.' }, 401);

    if (req.method === 'POST' && action === 'save') {
      const form = await req.formData();
      const type = form.get('type');
      const id = String(form.get('id') || crypto.randomUUID());
      if (type !== 'event' && type !== 'card') return json({ ok: false, error: 'Tipo de elemento no válido.' }, 400);

      const content = normalizeContent(await getContent(store));
      let item;
      try { item = JSON.parse(String(form.get('data') || '{}')); }
      catch { return json({ ok: false, error: 'Los datos del elemento no son válidos.' }, 400); }

      const file = form.get('image');
      if (file && typeof file.arrayBuffer === 'function' && file.size > 0) {
        const rawExt = String(file.type || '').split('/')[1] || 'jpg';
        const ext = rawExt.toLowerCase().replace('jpeg', 'jpg').replace(/[^a-z0-9]/g, '') || 'jpg';
        const key = `images/${type}-${id}.${ext}`;
        await store.set(key, Buffer.from(await file.arrayBuffer()), {
          metadata: { contentType: file.type || 'image/jpeg' }
        });
        item.image = `/.netlify/functions/admin?action=image&key=${encodeURIComponent(key)}`;
      }
      // Si no se manda una imagen, item.image queda sin definir y el merge conserva la imagen anterior.

      const list = type === 'event' ? content.events : content.cards;
      const index = list.findIndex(existing => existing.id === id);
      if (index >= 0) list[index] = { ...list[index], ...item, id };
      else list.push({ ...item, id });

      await store.setJSON('content.json', content);
      return json({ ok: true, ...content });
    }

    if (req.method === 'POST' && action === 'delete') {
      const body = await req.json();
      const type = body?.type;
      const id = body?.id;
      if ((type !== 'event' && type !== 'card') || !id) return json({ ok: false, error: 'Datos de eliminación no válidos.' }, 400);

      const content = normalizeContent(await getContent(store));
      const list = type === 'event' ? content.events : content.cards;
      const index = list.findIndex(item => item.id === id);
      if (index >= 0) list.splice(index, 1);

      await store.setJSON('content.json', content);
      return json({ ok: true, ...content });
    }

    return json({ ok: false, error: 'Acción no válida.' }, 400);
  } catch (error) {
    console.error(error);
    return json({ ok: false, error: error?.message || 'Error del servidor.' }, 500);
  }
};
