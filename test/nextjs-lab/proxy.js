import { NextResponse } from 'next/server';

export function proxy(request) {
  const owner = request.cookies.get('lab-role')?.value === 'owner';
  if (process.env.LAB_VARIANT !== 'vulnerable' && !owner) {
    return new NextResponse('DENIED_CONTROLLED_42', { status: 403 });
  }
  return NextResponse.next();
}
export const config = { matcher: ['/resource'] };
