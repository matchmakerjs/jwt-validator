import { JwtClaims } from '../model/jwt-claims';
import { ErrorSender } from '../resolver/error-sender';
import { JwtSignatureValidator } from './signature-validator';

export class JwtValidator {

    constructor(private signatureValidator: JwtSignatureValidator, private clockSkewInms: NonNullable<number> = 0) { }

    validateBearerToken(jws: string, errorSender: ErrorSender) {
        return new Promise<JwtClaims>(async (resolve, reject) => {
            if (!jws) {
                const response = {
                    message: 'Missing bearer token',
                };
                errorSender(400, response);
                reject(response);
                return;
            }
            try {
                const [headerB64, payloadB64, signatureB64] = jws.split('.');
                const payload: JwtClaims = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));

                if (payload.exp && Date.now() > ((payload.exp * 1000) + (this.clockSkewInms || 0))) {
                    const response = {
                        message: 'Expired token',
                        claims: payload
                    };
                    errorSender(401, response);
                    return reject(response);
                }
                this.signatureValidator.validate(
                    {
                        headerB64, payloadB64, signatureB64
                    },
                    errorSender)
                    .then(() => resolve(payload))
                    .catch(err => reject({
                        message: (err && typeof err === 'string') ? err : 'Token failed validation',
                        claims: payload
                    }));
            } catch (error) {
                // logger.error({ info: 'error validating token', error });
                const response = {
                    message: 'Invalid bearer token'
                };
                errorSender(401, response);
                reject(response);
            }
        });
    };
}