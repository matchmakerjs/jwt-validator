import { JsonWebKey } from '../encryption/web-key';

export interface KeyResolver{

    resolve(kid: string): Promise<JsonWebKey>;
}