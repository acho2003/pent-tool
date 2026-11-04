import type { NextApiRequest, NextApiResponse } from 'next';
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const destination = req.body.mode === 'one' ? 'https://safe.example.test/one' : 'https://safe.example.test/two';
  fetch(destination);
  return res.redirect(307, '/fixed');
}
