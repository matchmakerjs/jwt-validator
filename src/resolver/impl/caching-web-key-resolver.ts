import { JsonWebKey } from "../../encryption/web-key";
import { KeyResolver } from "../web-key-resolver";

export class CachingKeyResolver implements KeyResolver {

    private cache: {
        kid: string,
        key: JsonWebKey
    }[] = [];
    private cacheSize = 10;

    constructor(private keyResolver: KeyResolver, config?: { cacheSize: number }) {
        if (config?.cacheSize) this.cacheSize = config?.cacheSize;
    }

    resolve(kid: string): Promise<JsonWebKey> {
        const matched = this.cache.filter(it => it.kid === kid);
        console.log(matched.length ? 'key retrieved from cache' : 'key retrived from source');
        if (matched.length) return Promise.resolve(matched[0].key);
        return this.keyResolver.resolve(kid)
            .then(key => {
                if (this.cache.length >= this.cacheSize) {
                    this.cache = this.cache.slice(0, this.cacheSize - 1);
                }
                this.cache.unshift({ kid, key });
                return key;
            });
    }
}
