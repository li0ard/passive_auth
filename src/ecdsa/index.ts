import { ecdsa, weierstrass, type ECDSA } from "@noble/curves/abstract/weierstrass.js";
import { bytesToHex, bytesToNumberBE } from "@noble/curves/utils.js";
import type { CertificateChoices } from "@peculiar/asn1-cms";
import { id_ecPublicKey } from "@peculiar/asn1-ecc";
import { AsnConvert } from "@peculiar/asn1-schema";
import { HashHelper } from "../helpers/hash.js";
import { SpecifiedECDomain } from "../helpers/x509.js";

const OID_PRIME_FIELD = "1.2.840.10045.1.1";
const curveCache = new Map<string, ECDSA>();

/** Create `@noble/curves` ECDSA object from explicit curve parameters */
const curveFromECParams = (params: SpecifiedECDomain, hashOid: string): ECDSA => {
    const cacheKey = `${hashOid}_${bytesToHex(new Uint8Array(params.curve.a || [0]))}`;
    if (curveCache.has(cacheKey)) return curveCache.get(cacheKey)!;

    if(params.fieldID.fieldType != OID_PRIME_FIELD) throw new Error("Only explicit [X9.62] schema supported");

    const base = new Uint8Array(params.base).subarray(1);
    if (base.length % 2 !== 0) throw new Error(`Invalid base point length: ${base.length}`);
    const pointSize = base.length / 2;
    
    const curve = ecdsa(weierstrass({
        a: bytesToNumberBE(new Uint8Array(params.curve.a)),
        b: bytesToNumberBE(new Uint8Array(params.curve.b)),
        n: params.order,
        h: params.cofactor,
        p: params.fieldID.parameters,
        Gx: bytesToNumberBE(base.subarray(0, pointSize)),
        Gy: bytesToNumberBE(base.subarray(pointSize)),
    }), HashHelper.resolve(hashOid));

    curveCache.set(cacheKey, curve);
    return curve;
}

/** Extract curve parameters and public key from X.509 certificate and verify signature with ECDSA */
export const ecdsaVerify = (certificate: CertificateChoices, data: Uint8Array, signature: Uint8Array): boolean => {
    if(!certificate.certificate) throw new Error("Invalid certificate. Missing \"Certificate\" in \"CertificateChoices\"");
    const algorithm = certificate.certificate.tbsCertificate.subjectPublicKeyInfo.algorithm;
    if(algorithm.algorithm !== id_ecPublicKey) throw new Error("Invalid certificate. Certificate MUST use explicit curve parameters");
    if(!algorithm.parameters) throw new Error("Invalid certificate. Missing algorithm parameters");

    const params = AsnConvert.parse(algorithm.parameters, SpecifiedECDomain);
    const curve = curveFromECParams(params, certificate.certificate.signatureAlgorithm.algorithm);
    const publicKey = new Uint8Array(certificate.certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);

    return curve.verify(signature, data, publicKey, { format: "der", lowS: false });
}