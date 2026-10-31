import { role, state, READY, CHANGED } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET(request) { if (role(request) !== 'owner') return new Response('Denied', { status: 403 }); return Response.json({ state: state().changed ? CHANGED : READY }); }
