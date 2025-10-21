import { createClient } from 'redis';

const REDIS_URL = process.env.REDIS_URL || '';

let client: ReturnType<typeof createClient> | null = null;

async function getClient() {
  if (client) return client;
  if (!REDIS_URL) return null;
  client = createClient({ url: REDIS_URL });
  client.on('error', (err) => console.error('Redis Client Error', err));
  await client.connect();
  return client;
}

export async function getJson(key: string): Promise<any | null> {
  try {
    const c = await getClient();
    if (!c) return null;
    const v = await c.get(key);
    if (!v) return null;
    return JSON.parse(v);
  } catch (e) {
    console.warn('Redis getJson failed', e);
    return null;
  }
}

export async function setJson(key: string, value: any, ttlSeconds = 60): Promise<void> {
  try {
    const c = await getClient();
    if (!c) return;
    await c.set(key, JSON.stringify(value), { EX: ttlSeconds });
  } catch (e) {
    console.warn('Redis setJson failed', e);
  }
}

export async function del(key: string): Promise<void> {
  try {
    const c = await getClient();
    if (!c) return;
    await c.del(key);
  } catch (e) {
    console.warn('Redis del failed', e);
  }
}

export default { getJson, setJson, del };
