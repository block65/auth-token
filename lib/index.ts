/* eslint-disable camelcase */
import { AssertionError } from 'assert';

type Claims = Record<string, unknown>;

export interface AuthToken<TClaims extends Claims> {
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

export type CognitoIdTokenClaims = {
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  aud: string;
  token_use: 'id';
  origin_jti: string;
  event_id: string;
  'cognito:username': string;
  'cognito:groups': string[];
  auth_time: number;
  email: string;
};

export type CognitoGoogleIdTokenClaims = {
  token_use: 'id';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  aud: string;
  origin_jti: string;
  auth_time: number;
  at_hash: string;
  email_verified: boolean;
  'cognito:username': string;
  'cognito:groups': string[];
  email: string;
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
};

export type CognitoAccessTokenClaims = {
  token_use: 'access';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  jti: string;
  origin_jti: string;
  scope: string;
  auth_time: number;
  client_id: string;
  event_id: string;
  username: string;
  'cognito:groups': string[];
  device_key: string;
};

export type GoogleAccessTokenClaims = {
  version: 2;
  token_use: 'access';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  jti: string;
  origin_jti: string;
  scope: string;
  auth_time: number;
  client_id: string;
  username: string;
  'cognito:groups': string[];
};

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

export function createAuthToken<
  T extends CognitoAccessTokenClaims | GoogleAccessTokenClaims
>({
  jwt,
  ips,
  claims,
  userId,
}: {
  jwt: string;
  ips: string[];
  claims: Record<string, unknown>;
  userId?: string;
}): AuthToken<any> {
  const { jti, client_id, exp, iat, scope } = claims;

  assertString(jti, 'client_id is not a string');
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
    claims,
    isValid() {
      const nowSecs = Date.now() / 1000;
      return exp <= nowSecs && (!iat || iat >= nowSecs);
    },
  });
}
