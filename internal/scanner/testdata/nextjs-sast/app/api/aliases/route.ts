import { NextRequest, NextResponse } from 'next/server';
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const destination = searchParams.get('next');
  const parsed = new URL(request.url);
  await fetch(parsed.searchParams.get('url'));
  return NextResponse.redirect(destination);
}
