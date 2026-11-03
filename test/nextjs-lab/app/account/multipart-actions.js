'use server';
import { cookies } from 'next/headers';
import { state, vulnerable } from '../../lib/state.js';
export async function changeMultipartRecord(form) {
  const file = form.get('attachment');
  const data = file && new Uint8Array(await file.arrayBuffer());
  if (form.get('record') !== 'CONTROLLED_MULTIPART_42' || !data || data.length !== 5 || data[0] !== 0 || data[1] !== 255 || data[2] !== 42 || data[3] !== 13 || data[4] !== 10) throw new Error('Invalid synthetic multipart fixture');
  const actor = (await cookies()).get('lab-role')?.value;
  if (!vulnerable() && actor !== 'owner') throw new Error('Denied controlled multipart action');
  state().changed = true;
  state().actions++;
  return { changed: true };
}
