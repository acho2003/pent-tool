import type { NextApiRequest, NextApiResponse } from 'next';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { destination } = req.body;
  await fetch(destination);
  return res.redirect(destination);
}
