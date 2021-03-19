export interface JwtSignatureValidator {

    validate(headerB64: string, payloadB64: string, signatureB64: string): Promise<void>;
}