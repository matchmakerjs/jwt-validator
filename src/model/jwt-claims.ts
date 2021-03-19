export interface JwtClaims {
    "jti": string;
    "sub": string;
    "iss": string;
    "iat": number;
    "nbf": number;
    "exp": number;
    "aud": string | string[];
}
