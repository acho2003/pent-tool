import { NextRequest, NextResponse } from 'next/server';
export async function GET(req: NextRequest) {
  const selection = req.nextUrl.searchParams.get('next');
  const destination = selection === 'billing' ? '/billing' : '/account';
  await fetch('https://api.example.test/fixed');
  if (selection) return NextResponse.redirect(new URL(destination, req.url));
  return NextResponse.json({ value: process.env.NEXT_PUBLIC_API_URL });
}
export async function POST(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const destination = searchParams.get('selection') === 'billing' ? '/billing' : '/account';
  const parsed = new URL('https://api.example.test/?next=/fixed');
  await fetch('https://api.example.test/fixed');
  return NextResponse.redirect(new URL(destination, req.url));
}
