/* eslint-disable camelcase */
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
  claims: T;
  userId?: string;
}): Readonly<AuthToken<T>> {
  return Object.freeze({
    id: claims.jti,
    ips,
    jwt,
    userId,
    clientId: claims.client_id,
    scope: claims.scope.split(' '),
    expiresAt: claims.exp,
    ttl: claims.exp - claims.iat,
    claims,
    isValid() {
      const nowSecs = Date.now() / 1000;
      return claims.exp <= nowSecs && (!claims.iat || claims.iat >= nowSecs);
    },
  });
}
