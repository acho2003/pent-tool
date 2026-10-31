import { role, state } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function DELETE(request) { if (role(request) !== 'owner') return new Response('Denied', { status: 403 }); state().changed = false; state().cached = false; state().resets++; return new Response(null, { status: 204 }); }
