import { id_mgf1 } from "@peculiar/asn1-rsa"
import { mgf1, type VarLenHash } from "micro-rsa-dsa-dh/rsa.js"
import type { Hash } from "micro-rsa-dsa-dh/utils.js"

const RSA_PADDING_BY_OID: Readonly<Record<string, (hash: Hash) => VarLenHash>> = {
    [id_mgf1]: mgf1
}

export class RSAPaddingHelper {
    /**
     * Resolves RSA padding function by OID
     *
     * @param oid OID string
     * @throws {Error} If OID isn't supported
     */
    static resolve(oid: string): (hash: Hash) => VarLenHash {
        if (RSA_PADDING_BY_OID[oid]) return RSA_PADDING_BY_OID[oid]

        throw new Error(`Unknown RSA PADDING OID: ${oid}`)
    }
}
