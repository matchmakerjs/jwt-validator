import { JwtClaims } from "../model/jwt-claims";
import { ErrorSender } from "./error-sender";

export interface AccessClaimsResolver<E> {
    getClaims(request: E, errorSender: ErrorSender): Promise<JwtClaims>;
}
