import { vulnerable } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export async function GET(request) {
  if (!vulnerable()) return new Response('Denied', { status: 400 });
  const destination = new URL(new URL(request.url).searchParams.get('url') ?? '/', request.url);
  // The deliberately weak policy still confines this lab to its owned collector.
  if (destination.origin !== process.env.LAB_CALLBACK_ORIGIN || destination.pathname !== '/hit') return new Response('Outside lab', { status: 400 });
  await fetch(destination, { cache: 'no-store', redirect: 'error' });
  return new Response('Controlled fetch completed');
}
