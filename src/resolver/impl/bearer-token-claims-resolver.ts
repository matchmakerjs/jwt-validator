import { IncomingMessage } from "http";
import { JwtClaims } from "../../model/jwt-claims";
import { JwtValidator } from "../../validator/jwt-validator";
import { AccessClaimsResolver } from "../access-claims-resolver";

export class BearerTokenClaimsResolver implements AccessClaimsResolver<string>{

    constructor(private jwtValidator: JwtValidator) { }

    getClaims(header: string): Promise<JwtClaims> {
        if (!header) {
            return;
        }
        const authHeaderParts = header.split(' ');
        if (authHeaderParts.length != 2) {
            return Promise.reject("Authorization header should match 'Bearer *'");
        } else {
            return this.jwtValidator.validateBearerToken(authHeaderParts[1]);
        }
    }

    static forIncomingMessage(jwtValidator: JwtValidator): AccessClaimsResolver<IncomingMessage> {
        const accessClaimsResolver = new BearerTokenClaimsResolver(jwtValidator);
        return {
            getClaims: (request: IncomingMessage) => {
                return accessClaimsResolver.getClaims(request.headers['authorization']);
            }
        };
    }
}
