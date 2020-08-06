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

export interface IdTokenClaims {
  token_use: 'id';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  aud: string;
  origin_jti: string;
}

export interface CognitoIdTokenClaims extends IdTokenClaims {
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

export interface AccessTokenClaims {
  token_use: 'access';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
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

export function createAuthToken<
  T extends CognitoAccessTokenClaims | GoogleCognitoAccessTokenClaims
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
