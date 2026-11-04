import { labPath } from '../../lib/path.js';
import Discovery from './discovery.js';
export const dynamic = 'force-dynamic';
export default function Browser() { return <main><Discovery /><form method="post" action={labPath('/api/browser-write')}><button>Never submit during discovery</button></form></main>; }
