import type { NextApiRequest, NextApiResponse } from 'next';
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const destination = req.body.destination;
  fetch(destination);
  return res.redirect(307, destination);
}
