// Next replaces this public fixture-only prefix at build time for client code.
export function labPath(path) { return (process.env.NEXT_PUBLIC_LAB_BASE_PATH || '') + path; }
