import { NextRequest, NextResponse } from 'next/server';
import { redirect } from 'next/navigation';
export async function POST(request: NextRequest) {
  const { destination } = await request.json();
  await fetch(destination);
  return NextResponse.redirect(destination);
}
export async function PUT(request: Request) {
  const form = await request.formData();
  const destination = form.get('destination') as string;
  await fetch(destination);
  return NextResponse.redirect(destination);
}
export async function PATCH(request: Request) {
  const destination = await request.text();
  await fetch(destination);
  return redirect(destination);
}
export const DELETE = async (request: Request) => {
  const payload = await request.json();
  await fetch(payload.destination);
  return NextResponse.redirect(payload.destination);
};
