import http from 'node:http';
const hits = new Map();
const server = http.createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  const token = url.searchParams.get('scan_token') ?? '';
  response.setHeader('Cache-Control', 'no-store');
  if (url.pathname === '/health') { response.end('xalgorix-nextjs-lab-collector-v1'); return; }
  if (url.pathname === '/hit' && /^[a-f0-9]{32}$/.test(token)) { const count = (hits.get(token)?.count ?? 0) + 1; hits.set(token, { count, method: request.method }); response.end('Controlled lab callback'); return; }
  if (url.pathname === '/events' && /^[a-f0-9]{32}$/.test(token)) { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify({ token, count: hits.get(token)?.count ?? 0, method: hits.get(token)?.method ?? 'GET' })); return; }
  if (url.pathname === '/sink') { response.statusCode = 500; response.end('Redirect must not be followed'); return; }
  response.statusCode = 404; response.end('Not found');
});
server.listen(Number(process.env.PORT), '127.0.0.1');
process.on('SIGTERM', () => server.close());
