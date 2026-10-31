import { PRIVATE } from '../../lib/state.js';

export const dynamic = 'force-dynamic';
// The patched fixture authorizes in proxy.js before Next starts the RSC stream.
export default function Resource() {
  return <main><p>App Router controlled resource</p><p>{PRIVATE}</p></main>;
}
