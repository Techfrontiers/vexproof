import { verify } from 'jsonwebtoken';
import serialize from 'serialize-javascript';

export function verifyMerchantToken(token: string): { sub: string } {
  const secret = process.env.JWT_PUBLIC_KEY ?? 'placeholder-demo-key';
  return verify(token, secret) as { sub: string };
}

// Dead internal helper — never called or exported from any reachable runtime entrypoint
function legacyDeadDebugSerializer(payload: unknown): string {
  return serialize(payload);
}
