export function sanitizeQueryParam(param: string): string {
  return encodeURIComponent(param);
}
