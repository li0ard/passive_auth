import { sha1 } from "@noble/hashes/sha1"
import { sha256, sha384, sha512 } from "@noble/hashes/sha2"
import { AsnArray, AsnConvert, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema"
import { Attribute, type CertificateChoices, type CertificateSet } from "@peculiar/asn1-cms"
import { curveFromECParams, hashFromECDSAOID } from "@li0ard/ecdsa_icao"
import { ECParameters } from "@peculiar/asn1-ecc"
import { verify as verifyRSA, constants } from "crypto"

let alg: {[key: string]: any} = {
    "1.3.14.3.2.26": sha1,
    "2.16.840.1.101.3.4.2.1": sha256,
    "2.16.840.1.101.3.4.2.2": sha384,
    "2.16.840.1.101.3.4.2.3": sha512,

    // RSA signature
    "1.2.840.113549.1.1.5": "sha1",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.113549.1.1.14": "sha224"
}

/** Class for ASN1 schema of PKCS7 signed attributes */
@AsnType({ type: AsnTypeTypes.Set, itemType: Attribute })
export class SignedAttributes extends AsnArray<Attribute> {}

/**
 * Identify hash function by `oid` and hash `data`
 * @param oid OID of hash function
 * @param data Data to hash
 */
export const hash = (oid: string, data: Buffer): Buffer => {
    return Buffer.from(alg[oid](data))
}

/**
 * Encode buffer as PEM
 * @param data Data to encode
 * @param header PEM header
 */
export function pem(data: Buffer, header: string) {
    let str = `-----BEGIN ${header.toUpperCase()}-----\n${data.toString("base64").replace(/(.{64})/g, "$1\n")}\n-----END ${header.toUpperCase()}-----`
    return str
}

/**
 * Get certificates from `SET` by country code
 * @param certs Certificate set
 * @param code Country code (ex. `RU`)
 */
export const getCertsByCountryCode = (certs: CertificateSet, code: string) => {
    return certs.filter(
        k => k.certificate?.tbsCertificate.subject.filter(i => i[0].type == "2.5.4.6" && i[0].value == code)[0]
    )
}

/**
 * Verify `data` signature by certificate public key using ECDSA or RSA
 * @param cert Certificate
 * @param data Data
 * @param sig Signature of data
 */
export const verify = (cert: CertificateChoices, data: Buffer, sig: Buffer): boolean => {
    let isRSA = (Object.keys(alg).indexOf(cert.certificate?.signatureAlgorithm.algorithm as string) !== -1)
    let result = false
    if(!isRSA) {
        try {
            let hash = hashFromECDSAOID(cert.certificate?.signatureAlgorithm.algorithm as string)
            let params = AsnConvert.parse(cert.certificate?.tbsCertificate.subjectPublicKeyInfo.algorithm.parameters as ArrayBuffer, ECParameters)
            let curve = curveFromECParams(params, true)
            let pk = Buffer.from(cert.certificate?.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey as ArrayBuffer)
            let dataToCheck = Buffer.from(hash(data))
            let sigObj = curve.Signature.fromDER(sig)
            result = curve.verify(sigObj.normalizeS(), dataToCheck, pk)
        } catch(e) {}
    }
    else {
        try {
            let pk = Buffer.from(AsnConvert.serialize(cert.certificate?.tbsCertificate.subjectPublicKeyInfo))
            result = verifyRSA(
                alg[cert.certificate?.signatureAlgorithm.algorithm as string],
                data,
                {
                    key: pem(pk, "PUBLIC KEY"),
                    padding: constants.RSA_PKCS1_PSS_PADDING
                },
                sig
            )
        } catch(e) {}
    }

    return result
}