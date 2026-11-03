import { changeMultipartRecord } from '../account/multipart-actions.js';
export const dynamic = 'force-dynamic';
export default function Page() { return <main><form action={changeMultipartRecord}><input name="record" defaultValue="CONTROLLED_MULTIPART_42" /><input name="attachment" type="file" /><button type="submit">Submit controlled multipart fixture</button></form></main>; }
