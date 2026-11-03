export function loginRole(value) { return value === 'owner-fixture-session' ? 'owner' : value === 'reader-fixture-session' ? 'reader' : null; }
