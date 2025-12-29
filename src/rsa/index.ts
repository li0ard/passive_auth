import { bytesToNumberBE } from '@noble/curves/utils.js';
import type { CertificateChoices } from '@peculiar/asn1-cms';
import { id_rsaEncryption, RSAPublicKey, id_sha1WithRSAEncryption, id_sha256WithRSAEncryption, id_sha384WithRSAEncryption, id_sha512WithRSAEncryption, id_sha224WithRSAEncryption } from '@peculiar/asn1-rsa';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';

const PKCS1_ALGORITHMS_BY_OID: Readonly<Record<string, rsa.IPKCS>> = {
    [id_sha1WithRSAEncryption]: rsa.PKCS1_SHA1,
    [id_sha256WithRSAEncryption]: rsa.PKCS1_SHA256,
    [id_sha384WithRSAEncryption]: rsa.PKCS1_SHA384,
    [id_sha512WithRSAEncryption]: rsa.PKCS1_SHA512,
    [id_sha224WithRSAEncryption]: rsa.PKCS1_SHA224
}

/** Convert RSA public key from ASN.1 to object with `n` and `e` as `bigint` */
const convertSubjectPublicKey = (publicKey: ArrayBuffer): rsa.PublicKey => {
    const parsed = AsnConvert.parse(publicKey, RSAPublicKey);

    return {
        n: bytesToNumberBE(new Uint8Array(parsed.modulus)),
        e: bytesToNumberBE(new Uint8Array(parsed.publicExponent))
    }
}

/** Extract public key from X.509 certificate and verify signature with RSA PKCS#1 */
export const rsaVerify = (cert: CertificateChoices, data: Uint8Array, signature: Uint8Array): boolean => {
    if(!cert.certificate) throw new Error("Invalid certificate. Missing \"Certificate\" in \"CertificateChoices\"");
    const algorithm = cert.certificate.tbsCertificate.subjectPublicKeyInfo.algorithm;
    if(algorithm.algorithm !== id_rsaEncryption) throw new Error(`Invalid certificate. RSA certificate MUST use ${id_rsaEncryption} OID`);

    const pkcs1 = PKCS1_ALGORITHMS_BY_OID[cert.certificate.signatureAlgorithm.algorithm];
    if(!pkcs1) throw new Error(`Unsupported RSA PKCS#1 OID: ${cert.certificate.signatureAlgorithm.algorithm}`);
    const publicKey = convertSubjectPublicKey(cert.certificate.tbsCertificate.subjectPublicKeyInfo.subjectPublicKey);

    return pkcs1.verify(publicKey, data, signature);
}