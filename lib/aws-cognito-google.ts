import type {
  AwsCognitoAccessTokenClaims,
  AwsCognitoIdTokenClaims,
} from './aws-cognito.js';

export interface AwsCognitoGoogleAccessTokenClaims
  extends AwsCognitoAccessTokenClaims {
  version: 2;
}

export interface AwsCognitoGoogleIdTokenClaims extends AwsCognitoIdTokenClaims {
  origin_jti: string;
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
