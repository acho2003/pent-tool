export default function Item({ id }) { return <main><p>Observed dynamic test record: {id}</p></main>; }
export async function getServerSideProps({ params }) { return { props: { id: params.id } }; }
