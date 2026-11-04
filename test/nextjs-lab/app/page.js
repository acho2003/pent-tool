import { labPath } from '../lib/path.js';
export const dynamic = 'force-dynamic';
export default function Page() { return <main><p>Synthetic test data only.</p><a href={labPath('/account')}>Account action</a><a href={labPath('/legacy')}>Pages Router</a><a href={labPath('/items/controlled-record')}>Observed dynamic route</a></main>; }
