'use client';
import { useEffect, useState } from 'react';
export default function Discovery() {
  const [status, setStatus] = useState('Waiting for delayed hydration');
  useEffect(() => {
    const timer = setTimeout(() => {
      import('./late-reader.js').then(module => module.read()).then(setStatus);
      // Read-only discovery must intercept this write before it reaches Next.js.
      fetch('/api/browser-write', { method: 'POST', body: 'synthetic' }).catch(() => {});
    }, 650);
    return () => clearTimeout(timer);
  }, []);
  return <p>{status}</p>;
}
