import Discovery from '../browser/discovery.js';
export const dynamic = 'force-dynamic';
export default function Page() { return <main><p>Controlled router destination</p><Discovery /><form method="post" action="/api/browser-write"><button>Never submit during discovery</button></form></main>; }
