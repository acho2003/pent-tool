import { role } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET(request) { const actor = role(request); return Response.json({ role: actor }, { status: actor === 'anonymous' ? 401 : 200 }); }
