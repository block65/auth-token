import {
  GoogleCognitoIdTokenClaims,
  GoogleCognitoAccessTokenClaims,
  RegularAccessTokenClaims,
  RegularCognitoIdTokenClaims,
} from '../lib';

const idToken: RegularCognitoIdTokenClaims = {
  origin_jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  sub: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  aud: 'xxxxxx',
  'cognito:groups': ['admins'],
  event_id: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  token_use: 'id',
  auth_time: 111111111,
  iss:
    'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_xxxxxxxxxxxxxx',
  'cognito:username': 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  exp: 111111111,
  iat: 111111111,
  email: 'test@example.com',
};
const regularAccessToken: RegularAccessTokenClaims = {
  sub: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  device_key: 'ap-southeast-1_xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  'cognito:groups': ['admins'],
  iss:
    'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_xxxxxxxxxxxxxx',
  client_id: 'efefefefefefefefefefefefefefefe',
  origin_jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  event_id: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  token_use: 'access',
  scope: 'aws.cognito.signin.user.admin',
  auth_time: 111111111,
  exp: 111111111,
  iat: 111111111,
  jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  username: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
};

const googleAccessToken: GoogleCognitoAccessTokenClaims = {
  sub: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  'cognito:groups': ['ap-southeast-1_xxxxxxxxxxxxxx_Google'],
  iss:
    'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_xxxxxxxxxxxxxx',
  version: 2,
  client_id: 'efefefefefefefefefefefefefefefe',
  origin_jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  token_use: 'access',
  scope: 'openid https://api.colacube.dev/default email',
  auth_time: 111111111,
  exp: 111111111,
  iat: 111111111,
  jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  username: 'Google_9999999999999999999999999',
};

const googleIdToken: GoogleCognitoIdTokenClaims = {
  at_hash: 'HUILGYBUIKGYIKGYUKgyukGYUKgyukGYUK',
  sub: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  'cognito:groups': ['ap-southeast-1_xxxxxxxxxxxxxx_Google'],
  email_verified: false,
  iss:
    'https://cognito-idp.ap-southeast-1.amazonaws.com/ap-southeast-1_xxxxxxxxxxxxxx',
  'cognito:username': 'Google_99999999999999999999',
  origin_jti: 'xxxx-xxxxx-xxxxxx-xxxxxx-xxxxxxxxxxxx',
  aud: 'efefefefefefefefefefefefefefefe',
  identities: [
    {
      userId: '99999999999999999999999999',
      providerName: 'Google',
      providerType: 'Google',
      issuer: null,
      primary: 'true',
      dateCreated: '999999999999999',
    },
  ],
  token_use: 'id',
  auth_time: 111111111,
  exp: 11111111111,
  iat: 1111111111,
  email: 'test@example.com',
};
