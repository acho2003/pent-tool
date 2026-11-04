import type { NextApiRequest, NextApiResponse } from 'next';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const destination = req.query.destination as string;
  await fetch(destination);
  return res.redirect(307, destination);
}
