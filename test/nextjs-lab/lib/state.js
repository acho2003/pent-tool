export function state() {
  return globalThis.__xalgorixNextLab ??= { changed: false, cached: false, actions: 0, resets: 0 };
}
export function vulnerable() { return process.env.LAB_VARIANT === 'vulnerable'; }
export function role(request) {
  return /(?:^|;\s*)lab-role=(owner|reader)(?:;|$)/.exec(request.headers.get('cookie') ?? '')?.[1] ?? 'anonymous';
}
export const READY = 'CONTROLLED_READY_42';
export const CHANGED = 'CONTROLLED_CHANGED_42';
export const PRIVATE = 'PRIVATE_CONTROLLED_42';
export const DENIED = 'DENIED_CONTROLLED_42';
