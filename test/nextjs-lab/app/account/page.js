import { changeRecord } from './actions.js';
export const dynamic = 'force-dynamic';
export default function Account() { return <main><p>Controlled fixture action</p><form action={changeRecord}><button type="submit">Change the synthetic record</button></form></main>; }
