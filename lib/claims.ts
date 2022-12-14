interface CommonClaims {
  token_use?: 'access' | 'id';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  jti?: string;
}

export interface IdTokenClaims extends CommonClaims {
  token_use: 'id';
}

export interface AccessTokenClaims extends CommonClaims {
  client_id: string;
  token_use: 'access';
}

export interface AnyClaims {
  token_use?: 'access' | 'id';
  iss: string;
  iat: number;
  exp: number;
  sub: string;
  client_id: string;
  jti?: string;
}
