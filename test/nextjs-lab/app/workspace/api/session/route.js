import { loginRole } from '../../../../lib/login.js';
export const dynamic = 'force-dynamic';
export function GET(request) { const role = loginRole(request.cookies.get('lab-session')?.value); return Response.json({ role }, { status: role ? 200 : 403 }); }
