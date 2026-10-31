export default function Legacy({ record }) { return <main><p>Pages Router controlled resource</p><p>{record}</p></main>; }
export async function getServerSideProps({ req, res }) {
  const owner = /(?:^|;\s*)lab-role=owner(?:;|$)/.test(req.headers.cookie ?? '');
  if (!owner && process.env.LAB_VARIANT !== 'vulnerable') res.statusCode = 403;
  return { props: { record: owner || process.env.LAB_VARIANT === 'vulnerable' ? 'PRIVATE_CONTROLLED_42' : 'DENIED_CONTROLLED_42' } };
}
