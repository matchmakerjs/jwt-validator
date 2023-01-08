import * as crypto from 'crypto';
import { RSAPublicKeySpec } from "../encryption/rsa-public-key-spec";
import { JsonWebKey } from "../encryption/web-key";
import { ErrorSender } from '../resolver/error-sender';
import { KeyResolver } from "../resolver/web-key-resolver";
import { JwtSignatureValidator } from "./signature-validator";

export class RsaJwtSignatureValidator implements JwtSignatureValidator {

    constructor(private keyResolver: KeyResolver) { }

    validate(
        token: {
            headerB64: string,
            payloadB64: string,
            signatureB64: string
        },
        errorSender: ErrorSender
    ): Promise<void> {
        const { headerB64, payloadB64, signatureB64 } = token;
        return new Promise(async (resolve, reject) => {
            let jsonWebKey;
            try {
                jsonWebKey = await this.getJsonWebKey(headerB64, errorSender);
            } catch (error) {
                return reject(error);
            }
            try {
                const rsaPubKeySpec = new RSAPublicKeySpec(jsonWebKey);
                const isVerified = crypto.verify(
                    "sha256",
                    Buffer.from(headerB64 + '.' + payloadB64),
                    {
                        key: rsaPubKeySpec.getPem()
                    },
                    Buffer.from(signatureB64, 'base64')
                );
                if (!isVerified) {
                    const response = {
                        message: 'Bearer token failed verification'
                    };
                    errorSender(400, response);
                    return reject(response);
                }
                resolve();
            } catch (error) {
                reject('Unable to verify token');
            }
        });
    }

    private async getJsonWebKey(headerB64: string, errorSender: ErrorSender): Promise<JsonWebKey> {
        const headerJsonString = Buffer.from(headerB64, "base64").toString("utf8");
        const header: {
            alg: string,
            kid: string
        } = JSON.parse(headerJsonString);
        if (!header?.kid) {
            const response = {
                message: 'Invalid token: missing kid header'
            };
            errorSender(400, response);
            return Promise.reject(response);
        }
        return this.keyResolver.resolve(header.kid);
    }
}