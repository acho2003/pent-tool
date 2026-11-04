import { NextResponse } from 'next/server';
export async function POST(request: Request) {
  const body = await request.json();
  const destination = body.mode === 'one' ? 'https://safe.example.test/one' : 'https://safe.example.test/two';
  await fetch(destination);
  return NextResponse.redirect(new URL('/fixed', request.url));
}
export async function PUT(request: Request) {
  const response = await fetch('https://safe.example.test/config');
  const body = await response.json();
  await fetch(body.destination);
  return NextResponse.redirect(body.destination);
}
export async function PATCH(request: Request) {
  const form = await request.formData();
  const destination = form.get('mode') === 'one' ? 'https://safe.example.test/one' : 'https://safe.example.test/two';
  await fetch(destination);
  return NextResponse.redirect(new URL('/fixed', request.url));
}
export async function DELETE(request: Request) {
  const body = await request.json();
  await fetch('https://safe.example.test/fixed', { method: 'POST', body: JSON.stringify(body) });
  return NextResponse.redirect('/fixed', { status: 307, headers: { 'x-request': body.tag } });
}
