import { ErrorSender } from "../resolver/error-sender";

export interface JwtSignatureValidator {

    validate(
        token: {
            headerB64: string,
            payloadB64: string,
            signatureB64: string
        },
        errorSender: ErrorSender
    ): Promise<void>;
}