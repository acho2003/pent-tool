import { NextRequest, NextResponse } from 'next/server';
export async function GET(req: NextRequest) {
  const destination = req.nextUrl.searchParams.get('next');
  const source = req.nextUrl.searchParams.get('url');
  await fetch(source);
  if (destination) return NextResponse.redirect(destination);
  return NextResponse.json({ value: process.env.AUTH_SECRET });
}
