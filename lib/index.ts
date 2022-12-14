import { AssertionError } from 'node:assert';
import { BinaryLike, createHash, Encoding, Hash } from 'node:crypto';
import type { AnyClaims, IdTokenClaims } from './claims.js';

export * from './claims.js';
export * from './aws-cognito.js';
export * from './aws-cognito-google.js';
export * from './auth0.js';

export interface AuthToken<TClaims extends AnyClaims = never> {
  id: string;
  ips: string[];
  jwt: string;
  sub: string;
  scope: string[];
  claims: TClaims;
  isValid: () => boolean;
  issuedAt: Date;
  expiresAt: Date;
  ttl: number;
}

export interface IdToken<TClaims extends IdTokenClaims> {
  claims: TClaims;
  isValid: () => boolean;
  issuedAt: Date;
  expiresAt: Date;
  ttl: number;
}

export function withNullProto<T extends Record<string, unknown>>(
  obj: T
): T {
  return Object.assign(Object.create(null) as T, obj);
}

function assertString(val: unknown, message: string): asserts val is string {
  if (typeof val !== 'string') {
    throw new AssertionError({ message, actual: val, expected: String });
  }
}

function assertNumber(val: unknown, message: string): asserts val is number {
  if (typeof val !== 'number') {
    throw new AssertionError({ message, actual: val, expected: Number });
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (Object.prototype.toString.call(value) !== '[object Object]') {
    return false;
  }

  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === null || prototype === Object.getPrototypeOf({});
}

function assertPlainObject(
  val: unknown,
  message: string
): asserts val is Record<string, unknown> {
  if (!isPlainObject(val)) {
    throw new AssertionError({ message, actual: val, expected: Object });
  }
}

// async for future
export async function sha256(
  bufferOrString: BinaryLike,
  encoding: Encoding = 'utf-8'
): Promise<Hash> {
  const hash = createHash('sha256');
  if (typeof bufferOrString === 'string') {
    return hash.update(bufferOrString, encoding);
  }
  return hash.update(bufferOrString);
}

export async function createAuthToken<TClaims extends AnyClaims>({
  jwt,
  claims,
  ips,
}: {
  jwt: string;
  claims: TClaims;
  ips: string[];
}): Promise<AuthToken<TClaims>> {
  assertPlainObject(claims, 'claims is not a plain object');

  // eslint-disable-next-line @typescript-eslint/naming-convention
  const { jti, iss, sub, exp, iat, scope, client_id } = claims;

  assertString(sub, 'sub is not a string');
  assertString(client_id, 'client_id is not a string');
  assertString(iss, 'iss is not a string');
  assertString(scope, 'scope is not a string');
  assertNumber(iat, 'iat is not a number');
  assertNumber(exp, 'exp is not a number');

  const id = jti
    ? String(jti)
    : await sha256(jwt).then((hash) => hash.digest('base64url'));

  return withNullProto(
    Object.freeze({
      id,
      ips,
      jwt,
      sub,
      clientId: client_id,
      scope: scope.split(' '),
      issuedAt: new Date(iat * 1000),
      expiresAt: new Date(exp * 1000),
      ttl: exp - iat,
      claims,
      isValid() {
        const nowSecs = Date.now() / 1000;
        return exp <= nowSecs && (!iat || iat >= nowSecs);
      },
    })
  );
}

export function createIdToken<T extends IdTokenClaims>(
  claims: Partial<T> | unknown
): IdToken<T> {
  assertPlainObject(claims, 'claims is not a plain object');

  const { exp, iat } = claims;

  assertNumber(iat, 'iat is not a number');
  assertNumber(exp, 'exp is not a number');

  return Object.freeze({
    issuedAt: new Date(iat * 1000),
    expiresAt: new Date(exp * 1000),
    ttl: exp - iat,
    claims: claims as T,
    isValid() {
      const nowSecs = Date.now() / 1000;
      return exp <= nowSecs && (!iat || iat >= nowSecs);
    },
  });
}
