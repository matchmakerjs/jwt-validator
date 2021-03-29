import * as dayjs from 'dayjs';
import { JwtClaims } from '../model/jwt-claims';
import { JwtSignatureValidator } from './signature-validator';

export class JwtValidator {

    constructor(private signatureValidator: JwtSignatureValidator, private clockSkewInms: NonNullable<number> = 0) { }

    validateBearerToken(jws: string) {
        return new Promise<JwtClaims>(async (resolve, reject) => {
            if (!jws) {
                reject({
                    message: 'Missing bearer token',
                });
            }
            try {
                const [headerB64, payloadB64, signatureB64] = jws.split('.');
                const payload: JwtClaims = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
                if (!payload.exp || dayjs().isAfter(dayjs.unix(payload.exp).add(this.clockSkewInms, 'milliseconds'))) {
                    return reject({
                        message: 'Expired token',
                        token: payload
                    });
                }
                this.signatureValidator.validate(headerB64, payloadB64, signatureB64)
                    .then(() => resolve(payload))
                    .catch(err => reject({
                        message: (err && typeof err === 'string') ? err : 'Token failed validation',
                        token: payload
                    }));
            } catch (error) {
                // logger.error({ info: 'error validating token', error });
                reject({
                    message: 'Invalid bearer token'
                });
            }
        });
    };
}