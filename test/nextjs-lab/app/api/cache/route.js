import { role, state, vulnerable, PRIVATE, DENIED } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET(request) {
  const owner = role(request) === 'owner';
  const bypass = new URL(request.url).searchParams.get('uncached') === '1';
  const leak = vulnerable() && state().cached && !bypass;
  if (owner) { if (!bypass) state().cached = true; return Response.json({ record: PRIVATE }, { headers: { 'Cache-Control': 'private, no-store' } }); }
  if (leak) return Response.json({ record: PRIVATE }, { headers: { 'X-Cache': 'HIT', 'Cache-Control': 'public, max-age=60' } });
  return new Response(DENIED, { status: 403, headers: { 'Cache-Control': 'no-store' } });
}
