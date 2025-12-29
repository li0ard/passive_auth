import { sha1 } from "@noble/hashes/legacy.js";
import { sha256, sha384, sha512, sha224 } from "@noble/hashes/sha2.js";
import type { CHash } from "@noble/hashes/utils.js";
import { id_ecdsaWithSHA1, id_ecdsaWithSHA224, id_ecdsaWithSHA256, id_ecdsaWithSHA384, id_ecdsaWithSHA512 } from "@peculiar/asn1-ecc";
import { id_sha1, id_sha224, id_sha256, id_sha384, id_sha512 } from "@peculiar/asn1-rsa";

const HASH_ALGORITHMS_BY_OID: Readonly<Record<string, CHash>> = {
    [id_sha1]: sha1,
    [id_sha256]: sha256,
    [id_sha384]: sha384,
    [id_sha512]: sha512,
    [id_sha224]: sha224
}

const HASH_ALGORITHMS_BY_ECDSA_OID: Readonly<Record<string, CHash>> = {
    [id_ecdsaWithSHA1]: sha1,
    [id_ecdsaWithSHA224]: sha224,
    [id_ecdsaWithSHA256]: sha256,
    [id_ecdsaWithSHA384]: sha384,
    [id_ecdsaWithSHA512]: sha512
}

export class HashHelper {
    /**
     * Resolves hash function by OID
     * 
     * Supports NIST OIDs and ECDSA's OIDs
     * @param oid OID string
     * @throws {Error} If OID isn't supported
     */
    static resolve(oid: string): CHash {
        if(HASH_ALGORITHMS_BY_OID[oid]) return HASH_ALGORITHMS_BY_OID[oid];
        if(HASH_ALGORITHMS_BY_ECDSA_OID[oid]) return HASH_ALGORITHMS_BY_ECDSA_OID[oid];

        throw new Error(`Unknown OID: ${oid}`);
    }

    /**
     * Hashes data using algorithm identified by OID
     * @param oid OID string
     * @param data Data to hash
     * @throws {Error} If OID isn't supported
     */
    static hash(oid: string, data: Uint8Array): Uint8Array { return HashHelper.resolve(oid)(data); }
}