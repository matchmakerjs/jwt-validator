import { JwtClaims } from "../model/jwt-claims";

export interface AccessClaimsResolver<E> {
    getClaims(request: E): Promise<JwtClaims>;
}
