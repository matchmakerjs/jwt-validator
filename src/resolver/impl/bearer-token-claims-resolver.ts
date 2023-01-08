import { IncomingMessage } from "http";
import { JwtClaims } from "../../model/jwt-claims";
import { JwtValidator } from "../../validator/jwt-validator";
import { AccessClaimsResolver } from "../access-claims-resolver";
import { ErrorSender } from "../error-sender";

export class BearerTokenClaimsResolver implements AccessClaimsResolver<string>{

    constructor(private jwtValidator: JwtValidator) { }

    getClaims(header: string, errorSender: ErrorSender): Promise<JwtClaims> {
        if (!header) {
            return;
        }
        const authHeaderParts = header.split(' ');
        if (authHeaderParts.length != 2) {
            const response = {
                message: "Authorization header should match 'Bearer *'"
            };
            errorSender(400, response);
            return Promise.reject(response);
        } else {
            return this.jwtValidator.validateBearerToken(authHeaderParts[1], errorSender);
        }
    }

    static forIncomingMessage(jwtValidator: JwtValidator): AccessClaimsResolver<IncomingMessage> {
        const accessClaimsResolver = new BearerTokenClaimsResolver(jwtValidator);
        return {
            getClaims: (request: IncomingMessage, errorSender: ErrorSender) => {
                return accessClaimsResolver.getClaims(request.headers['authorization'], errorSender);
            }
        };
    }
}
