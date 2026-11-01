import { role, state } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function POST() { state().browserWrites = (state().browserWrites ?? 0) + 1; return Response.json({ changed: true }); }
export function GET(request) { if (role(request) !== 'owner') return new Response('Denied', { status: 403 }); return Response.json({ writes: state().browserWrites ?? 0, reads: state().browserReads ?? {} }); }
