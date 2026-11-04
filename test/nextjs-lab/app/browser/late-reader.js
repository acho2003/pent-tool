import { labPath } from '../../lib/path.js';
export async function read() { const response = await fetch(labPath('/api/browser-read?stage=lazy')); const data = await response.json(); return 'Browser identity: ' + data.role; }
