import { vulnerable } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET(request) {
  const destination = new URL(request.url).searchParams.get('next') ?? '/account';
  const incoming = new URL(request.url);
  const visibleOrigin = `${incoming.protocol}//${request.headers.get('host')}`;
  const resolved = new URL(destination, visibleOrigin);
  if (!vulnerable() && resolved.origin !== visibleOrigin) return new Response('Denied', { status: 400 });
  return new Response(null, { status: 302, headers: { Location: resolved.href } });
}
