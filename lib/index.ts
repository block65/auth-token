/* eslint-disable camelcase */
import { AssertionError } from 'assert';

export interface AuthToken<TClaims extends AccessTokenClaims> {
  id: string;
  ips: string[];
  jwt: string;
  clientId: string;
  userId: string | undefined;
  scope: string[];
  claims: TClaims;
  isValid: () => boolean;
  expiresAt: number;
  ttl: number;
}
export interface IdToken<TClaims extends IdTokenClaims> {
  id: string;
  userId: string | undefined;
  claims: TClaims;
  isValid: () => boolean;
  expiresAt: number;
  ttl: number;
}

export interface TokenClaims {
  token_use: 'access' | 'id';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
}

export interface IdTokenClaims extends TokenClaims {
  token_use: 'id';
  origin_jti: string;
}

export interface CognitoIdTokenClaims extends IdTokenClaims {
  aud: string;
  auth_time: number;
  email: string;
  'cognito:username': string;
  'cognito:groups': string[];
}

export interface GoogleCognitoIdTokenClaims extends CognitoIdTokenClaims {
  at_hash: string;
  email_verified: boolean;
  identities: [
    {
      userId: string;
      providerName: 'Google';
      providerType: 'Google';
      issuer: null;
      primary: 'true';
      dateCreated: string;
    },
  ];
}

export interface RegularCognitoIdTokenClaims extends CognitoIdTokenClaims {
  event_id: string;
}

export interface AccessTokenClaims extends TokenClaims {
  token_use: 'access';
  jti: string;
}

export interface CognitoAccessTokenClaims extends AccessTokenClaims {
  origin_jti: string;
  scope: string;
  client_id: string;
  auth_time: number;
  username: string;
  'cognito:groups': string[];
}

export interface RegularAccessTokenClaims extends CognitoAccessTokenClaims {
  event_id: string;
  device_key: string;
}

export interface GoogleCognitoAccessTokenClaims
  extends CognitoAccessTokenClaims {
  version: 2;
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

function isPlainObject(value: any): value is Record<string, unknown> {
  if (Object.prototype.toString.call(value) !== '[object Object]') {
    return false;
  }

  const prototype = Object.getPrototypeOf(value);
  return prototype === null || prototype === Object.getPrototypeOf({});
}

function assertPlainObject(
  val: unknown,
  message: string,
): asserts val is Record<string, unknown> {
  if (!isPlainObject(val)) {
    throw new AssertionError({ message, actual: val, expected: Object });
  }
}

export function createAuthToken<
  T extends AccessTokenClaims = AccessTokenClaims
>({
  jwt,
  ips,
  claims,
  userId,
}: {
  jwt: string;
  ips: string[];
  claims: Record<keyof T, unknown> | unknown;
  userId?: string;
}): AuthToken<T> {
  assertPlainObject(claims, 'claims is not a plain object');

  const { jti, client_id, exp, iat, scope } = claims;

  assertString(jti, 'jti is not a string');
  assertString(client_id, 'client_id is not a string');
  assertString(scope, 'scope is not a string');
  assertNumber(exp, 'exp is not a number');
  assertNumber(iat, 'iat is not a number');

  return Object.freeze({
    id: jti,
    ips,
    jwt,
    userId,
    clientId: client_id,
    scope: scope.split(' '),
    expiresAt: exp,
    ttl: exp - iat,
    claims: claims as T,
    isValid() {
      const nowSecs = Date.now() / 1000;
      return exp <= nowSecs && (!iat || iat >= nowSecs);
    },
  });
}

export function createIdToken<T extends IdTokenClaims = IdTokenClaims>({
  jwt,
  claims,
  userId,
}: {
  jwt: string;
  ips: string[];
  claims: Record<keyof T, unknown> | unknown;
  userId?: string;
}): IdToken<T> {
  assertPlainObject(claims, 'claims is not a plain object');

  const { origin_jti, exp, iat } = claims;

  assertString(origin_jti, 'origin_jti is not a string');
  assertNumber(exp, 'exp is not a number');
  assertNumber(iat, 'iat is not a number');

  return Object.freeze({
    id: origin_jti,
    jwt,
    userId,
    expiresAt: exp,
    ttl: exp - iat,
    claims: claims as T,
    isValid() {
      const nowSecs = Date.now() / 1000;
      return exp <= nowSecs && (!iat || iat >= nowSecs);
    },
  });
}
