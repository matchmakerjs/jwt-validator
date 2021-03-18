import { JsonWebKey } from "./web-key";

export class RSAPublicKeySpec {

    private pem: string;

    constructor(private key: JsonWebKey) {
        if (!key.n || !key.e) {
            throw new Error('invalid key');
        }
    }

    getPem() {
        if (this.pem) {
            return this.pem;
        }
        const modulus = Buffer.from(this.key.n, 'base64');
        const exponent = Buffer.from(this.key.e, 'base64');

        let modulusHex = modulus.toString('hex');
        let exponentHex = exponent.toString('hex');

        modulusHex = this.prepadSigned(modulusHex);
        exponentHex = this.prepadSigned(exponentHex);

        const modlen = modulusHex.length / 2;
        const explen = exponentHex.length / 2;

        const encodedModlen = this.encodeLengthHex(modlen);
        const encodedExplen = this.encodeLengthHex(explen);
        const encodedPubkey = '30' +
            this.encodeLengthHex(
                modlen +
                explen +
                encodedModlen.length / 2 +
                encodedExplen.length / 2 + 2
            ) +
            '02' + encodedModlen + modulusHex +
            '02' + encodedExplen + exponentHex;

        const derB64 = Buffer.from(encodedPubkey, 'hex').toString('base64');
        this.pem = '-----BEGIN RSA PUBLIC KEY-----\n'
            + derB64.match(/.{1,64}/g)?.join('\n')
            + '\n-----END RSA PUBLIC KEY-----\n';
        return this.pem;
    }

    prepadSigned(hexStr: string) {
        const msb = hexStr[0]
        if (msb < '0' || msb > '7') {
            return '00' + hexStr;
        } else {
            return hexStr;
        }
    }

    // encode ASN.1 DER length field
    // if <=127, short form
    // if >=128, long form
    encodeLengthHex(n: number) {
        if (n <= 127) return this.toHex(n)
        else {
            const nHex = this.toHex(n)
            const lengthOfLengthByte = 128 + nHex.length / 2 // 0x80+numbytes
            return this.toHex(lengthOfLengthByte) + nHex
        }
    }

    toHex(num: number) {
        const nstr = num.toString(16);
        if (nstr.length % 2) return '0' + nstr;
        return nstr;
    }
}