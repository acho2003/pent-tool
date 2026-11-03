import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { loginRole } from '../../../lib/login.js';
export const dynamic = 'force-dynamic';
export default async function Dashboard() { const role = loginRole((await cookies()).get('lab-session')?.value); if (!role) redirect('/workspace/login'); return <main><p>LOGIN_CONTROLLED_42</p><p>Signed in as {role}</p></main>; }
