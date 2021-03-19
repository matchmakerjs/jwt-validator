import * as crypto from 'crypto';
import { RSAPublicKeySpec } from "../encryption/rsa-public-key-spec";
import { JsonWebKey } from "../encryption/web-key";
import { KeyResolver } from "../resolver/web-key-resolver";
import { JwtSignatureValidator } from "./signature-validator";

export class RsaJwtSignatureValidator implements JwtSignatureValidator {

    constructor(private keyResolver: KeyResolver) { }

    validate(headerB64: string, payloadB64: string, signatureB64: string): Promise<void> {
        return new Promise(async (resolve, reject) => {
            let jsonWebKey;
            try {
                jsonWebKey = await this.getJsonWebKey(headerB64);
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
                    return reject('Bearer token failed verification');
                }
                resolve();
            } catch (error) {
                // logger.error(error);
                reject('Unable to verify token');
            }
        });
    }

    private async getJsonWebKey(headerB64: string): Promise<JsonWebKey> {
        const headerJsonString = Buffer.from(headerB64, "base64").toString("utf8");
        const header: {
            alg: string,
            kid: string
        } = JSON.parse(headerJsonString);
        if (!header.kid) {
            return Promise.reject('Invalid kid header');
        }
        return this.keyResolver.resolve(header.kid);
    }
}