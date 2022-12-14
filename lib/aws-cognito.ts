import type { AccessTokenClaims, IdTokenClaims } from './claims.js';

export interface AwsCognitoIdTokenClaims extends IdTokenClaims {
  aud: string;
  auth_time: number;
  email: string;
  'cognito:username': string;
  'cognito:groups': string[];
}

export interface AwsCognitoRegularIdTokenClaims
  extends AwsCognitoIdTokenClaims {
  event_id: string;
}

export interface AwsCognitoAccessTokenClaims extends AccessTokenClaims {
  origin_jti: string;
  scope: string;
  client_id: string;
  auth_time: number;
  username: string;
  'cognito:groups': string[];
}

export interface CognitoClientAccessTokenClaims extends AccessTokenClaims {
  version: 2;
  auth_time: number;
  scope: string;
  client_id: string;
}

export interface AwsCognitoRegularAccessTokenClaims
  extends AwsCognitoAccessTokenClaims {
  event_id: string;
  device_key: string;
}
