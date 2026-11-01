import { role, state } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET(request) { const identity = role(request); const counters = state().browserReads ??= {}; counters[identity] = (counters[identity] ?? 0) + 1; return Response.json({ role: identity }); }
