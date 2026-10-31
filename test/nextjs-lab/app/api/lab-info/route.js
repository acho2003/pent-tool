import { state, vulnerable } from '../../../lib/state.js';
export const dynamic = 'force-dynamic';
export function GET() { return Response.json({ fixture: 'xalgorix-nextjs-lab-v1', variant: vulnerable() ? 'vulnerable' : 'patched', callback: process.env.LAB_CALLBACK_ORIGIN, ...state() }); }
