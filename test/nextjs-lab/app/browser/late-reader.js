export async function read() { const response = await fetch('/api/browser-read?stage=lazy'); const data = await response.json(); return 'Browser identity: ' + data.role; }
