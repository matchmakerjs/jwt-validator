import * as dayjs from 'dayjs';
import { JwtClaims } from '../model/jwt-claims';
import { JwtSignatureValidator } from './signatur-validator';

export class JwtValidator {

    constructor(private signatureValidator: JwtSignatureValidator, private clockSkewInms: NonNullable<number> = 0) { }

    validateBearerToken(jws: string) {
        return new Promise<JwtClaims>(async (resolve, reject) => {
            if (!jws) {
                reject('Invalid bearer token');
            }
            try {
                const [headerB64, payloadB64, signatureB64] = jws.split('.');
                const payload: JwtClaims = JSON.parse(Buffer.from(payloadB64, "base64").toString("utf8"));
                if (!payload.exp || dayjs().isAfter(dayjs.unix(payload.exp).add(this.clockSkewInms, 'milliseconds'))) {
                    return reject({
                        description: 'Expired token',
                        ...payload
                    });
                }
                this.signatureValidator.validate(headerB64, payloadB64, signatureB64)
                    .then(() => resolve(payload))
                    .catch(err => reject(err));
            } catch (error) {
                // logger.error({ info: 'error validating token', error });
                reject('Invalid bearer token');
            }
        });
    };
}