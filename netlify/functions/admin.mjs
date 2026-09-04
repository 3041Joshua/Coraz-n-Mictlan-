import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';
import defaultContent from './default-content.mjs';

const cookieName = 'cm_admin';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
  });
}

function getSecret() { return Netlify.env.get('ADMIN_PASSWORD') || ''; }

function createToken(secret) {
  const exp = Date.now() + 1000 * 60 * 60 * 12;
  const raw = `admin.${exp}`;
  const sig = crypto.createHmac('sha256', secret).update(raw).digest('hex');
  return `${raw}.${sig}`;
}

function readCookie(req) {
  const cookie = req.headers.get('cookie') || '';
  return cookie.split(';').map(p => p.trim()).find(p => p.startsWith(`${cookieName}=`))?.slice(cookieName.length + 1) || '';
}

function validToken(req, secret) {
  const value = readCookie(req);
  if (!secret || !value) return false;
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  const [kind, exp, sig] = parts;
  if (kind !== 'admin' || !exp || !sig || Number(exp) < Date.now()) return false;
  const expected = crypto.createHmac('sha256', secret).update(`admin.${exp}`).digest('hex');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a,b);
}

function normalizeContent(content = {}) {
  return {
    events: Array.isArray(content.events) ? content.events : [],
    cards: Array.isArray(content.cards) ? content.cards : [],
    bios: {
      zoe: { ...defaultContent.bios.zoe, ...(content.bios?.zoe || {}) },
      juda: { ...defaultContent.bios.juda, ...(content.bios?.juda || {}) }
    },
    catalogs: {
      zoe: Array.isArray(content.catalogs?.zoe) ? content.catalogs.zoe : defaultContent.catalogs.zoe,
      juda: Array.isArray(content.catalogs?.juda) ? content.catalogs.juda : defaultContent.catalogs.juda
    }
  };
}

async function getContent(store) {
  const stored = await store.get('content.json', { type: 'json' });
  return normalizeContent(stored || defaultContent);
}

function imageResponse(result) {
  return new Response(result.data, {
    headers: {
      'content-type': result.metadata?.contentType || 'application/octet-stream',
      'cache-control': 'public, max-age=31536000, immutable'
    }
  });
}

export default async (req) => {
  try {
    const store = getStore({ name: 'corazon-mictlan', consistency: 'strong' });
    const url = new URL(req.url);
    const action = url.searchParams.get('action');
    const secret = getSecret();

    if (req.method === 'POST' && action === 'login') {
      if (!secret) return json({ ok:false, error:'Falta configurar ADMIN_PASSWORD en Netlify.' },500);
      const body = await req.json();
      if (!body?.password || body.password !== secret) return json({ok:false,error:'Contraseña incorrecta.'},401);
      return json({ok:true},200,{'set-cookie':`${cookieName}=${createToken(secret)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`});
    }

    if (req.method === 'POST' && action === 'logout') {
      return json({ok:true},200,{'set-cookie':`${cookieName}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`});
    }

    if (req.method === 'GET' && action === 'image') {
      const key=url.searchParams.get('key');
      if (!key || !key.startsWith('images/')) return new Response('Not found',{status:404});
      const result=await store.getWithMetadata(key,{type:'arrayBuffer'});
      if (!result) return new Response('Not found',{status:404});
      return imageResponse(result);
    }

    if (req.method === 'GET' && action === 'public') {
      const content=await getContent(store);
      return json({ok:true,events:content.events.filter(x=>x.active!==false),cards:content.cards.filter(x=>x.active!==false),bios:{zoe:content.bios.zoe.active===false?null:content.bios.zoe,juda:content.bios.juda.active===false?null:content.bios.juda},catalogs:{zoe:content.catalogs.zoe.filter(x=>x.active!==false),juda:content.catalogs.juda.filter(x=>x.active!==false)}});
    }

    if (req.method === 'GET' && action === 'admin') {
      if (!validToken(req,secret)) return json({ok:false,error:'No autorizado.'},401);
      return json({ok:true,...await getContent(store)});
    }

    if (!validToken(req,secret)) return json({ok:false,error:'No autorizado.'},401);

    if (req.method === 'POST' && action === 'upload-chunk') {
      const uploadId=req.headers.get('x-upload-id')||'';
      const chunkIndex=Number(req.headers.get('x-chunk-index'));
      const totalChunks=Number(req.headers.get('x-total-chunks'));
      const contentType=req.headers.get('x-file-type')||'image/jpeg';
      if (!/^[a-zA-Z0-9_-]{10,100}$/.test(uploadId)) return json({ok:false,error:'Identificador de subida no válido.'},400);
      if (!Number.isInteger(chunkIndex)||chunkIndex<0||!Number.isInteger(totalChunks)||totalChunks<1||totalChunks>100) return json({ok:false,error:'Datos de bloque no válidos.'},400);
      const body=await req.arrayBuffer();
      if (!body.byteLength||body.byteLength>2*1024*1024) return json({ok:false,error:'Bloque demasiado grande.'},413);
      await store.set(`chunks/${uploadId}/${chunkIndex}`,body,{metadata:{contentType,totalChunks:String(totalChunks)}});
      return json({ok:true,chunkIndex});
    }

    if (req.method === 'POST' && action === 'upload-finish') {
      let body; try { body=await req.json(); } catch { return json({ok:false,error:'Datos de subida no válidos.'},400); }
      const uploadId=String(body?.uploadId||'');
      const totalChunks=Number(body?.totalChunks);
      const contentType=String(body?.contentType||'image/jpeg');
      if (!/^[a-zA-Z0-9_-]{10,100}$/.test(uploadId)||!Number.isInteger(totalChunks)||totalChunks<1||totalChunks>100) return json({ok:false,error:'Datos de subida no válidos.'},400);
      if (!contentType.startsWith('image/')) return json({ok:false,error:'El archivo no es una imagen.'},400);
      const parts=[]; let totalBytes=0;
      for(let i=0;i<totalChunks;i++){
        const part=await store.get(`chunks/${uploadId}/${i}`,{type:'arrayBuffer'});
        if(part===null) return json({ok:false,error:`Falta el bloque ${i+1} de ${totalChunks}.`},400);
        parts.push(part); totalBytes+=part.byteLength;
        if(totalBytes>20*1024*1024) return json({ok:false,error:'La imagen supera el máximo de 20 MB.'},413);
      }
      const merged=new Uint8Array(totalBytes); let offset=0;
      for(const part of parts){merged.set(new Uint8Array(part),offset);offset+=part.byteLength;}
      const ext=contentType.split('/')[1]?.toLowerCase().replace('jpeg','jpg').replace(/[^a-z0-9]/g,'')||'jpg';
      const key=`images/${crypto.randomUUID()}.${ext}`;
      await store.set(key,merged.buffer,{metadata:{contentType}});
      await Promise.all(Array.from({length:totalChunks},(_,i)=>store.delete(`chunks/${uploadId}/${i}`)));
      return json({ok:true,image:`/.netlify/functions/admin?action=image&key=${encodeURIComponent(key)}`});
    }

    if (req.method === 'POST' && action === 'save') {
      let body; try { body=await req.json(); } catch { return json({ok:false,error:'Datos no válidos.'},400); }
      const type=body?.type;
      const id=String(body?.id||crypto.randomUUID());
      const data=body?.data&&typeof body.data==='object'?body.data:{};
      const content=await getContent(store);
      let list=null;
      if(type==='event') list=content.events;
      else if(type==='card') list=content.cards;
      else if(type==='artwork-zoe') list=content.catalogs.zoe;
      else if(type==='artwork-juda') list=content.catalogs.juda;
      else if(type==='bio-zoe') content.bios.zoe={...content.bios.zoe,...data,id:'zoe'};
      else if(type==='bio-juda') content.bios.juda={...content.bios.juda,...data,id:'juda'};
      else return json({ok:false,error:'Tipo de elemento no válido.'},400);

      if(list){
        const index=list.findIndex(x=>x.id===id);
        if(index>=0) list[index]={...list[index],...data,id}; else list.push({...data,id});
      }
      await store.setJSON('content.json',content);
      return json({ok:true,...content});
    }

    if (req.method === 'POST' && action === 'delete') {
      let body; try { body=await req.json(); } catch { return json({ok:false,error:'Datos de eliminación no válidos.'},400); }
      const type=body?.type, id=body?.id;
      const content=await getContent(store);
      let list=null;
      if(type==='event') list=content.events;
      else if(type==='card') list=content.cards;
      else if(type==='artwork-zoe') list=content.catalogs.zoe;
      else if(type==='artwork-juda') list=content.catalogs.juda;
      else return json({ok:false,error:'Tipo de elemento no válido.'},400);
      const index=list.findIndex(x=>x.id===id); if(index>=0) list.splice(index,1);
      await store.setJSON('content.json',content);
      return json({ok:true,...content});
    }

    return json({ok:false,error:'Acción no válida.'},400);
  } catch(error) {
    console.error(error);
    return json({ok:false,error:error?.message||'Error del servidor.'},500);
  }
};
