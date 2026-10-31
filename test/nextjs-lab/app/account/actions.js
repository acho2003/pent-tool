'use server';
import { cookies } from 'next/headers';
import { state, vulnerable } from '../../lib/state.js';
export async function changeRecord() {
  const actor = (await cookies()).get('lab-role')?.value;
  if (!vulnerable() && actor !== 'owner') throw new Error('Denied controlled action');
  state().changed = true;
  state().actions++;
  return { changed: true };
}
