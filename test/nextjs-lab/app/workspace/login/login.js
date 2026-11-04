'use client';
import { labPath } from '../../../lib/path.js';
import { useState } from 'react';
import { useRouter } from 'next/navigation';
export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState('');
  async function submit(event) {
    event.preventDefault();
    const response = await fetch(labPath('/workspace/api/login'), { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email, password }) });
    if (response.ok) router.push('/workspace/dashboard');
    else setStatus('Synthetic credentials rejected');
  }
  return <form onSubmit={submit}><label>Email<input name="email" type="email" value={email} onChange={event => setEmail(event.target.value)} /></label><label>Password<input name="password" type="password" value={password} onChange={event => setPassword(event.target.value)} /></label><button type="submit">Sign in</button><p>{status}</p></form>;
}
