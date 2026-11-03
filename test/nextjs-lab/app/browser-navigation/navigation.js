'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
export default function Navigation() { const router = useRouter(); useEffect(() => { const timer = setTimeout(() => router.push('/browser-arrived'), 350); return () => clearTimeout(timer); }, [router]); return <p>Waiting for a controlled client-side navigation</p>; }
