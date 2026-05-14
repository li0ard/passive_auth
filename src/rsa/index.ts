import { bytesToNumberBE } from '@noble/curves/utils.js';
import { DigestAlgorithmIdentifier, type CertificateChoices } from '@peculiar/asn1-cms';
import { RsaSaPssParams, id_rsaEncryption, RSAPublicKey, id_sha1WithRSAEncryption, id_sha256WithRSAEncryption, id_sha384WithRSAEncryption, id_sha512WithRSAEncryption, id_sha224WithRSAEncryption, id_RSASSA_PSS } from '@peculiar/asn1-rsa';
import { AsnConvert } from '@peculiar/asn1-schema';
import * as rsa from 'micro-rsa-dsa-dh/rsa.js';
import { HashHelper } from '../helpers/hash';
import { RSAPaddingHelper } from './padding';

const PKCS1_ALGORITHMS_BY_OID: Readonly<Record<string, rsa.IPKCS>> = {
    [id_sha1WithRSAEncryption]: rsa.PKCS1_SHA1,
    [id_sha256WithRSAEncryption]: rsa.PKCS1_SHA256,
    [id_sha384WithRSAEncryption]: rsa.PKCS1_SHA384,
    [id_sha512WithRSAEncryption]: rsa.PKCS1_SHA512,
    [id_sha224WithRSAEncryption]: rsa.PKCS1_SHA224
};

/** Convert RSA public key from ASN.1 to object with `n` and `e` as `bigint` */
const convertSubjectPublicKey = (publicKey: ArrayBuffer): rsa.PublicKey => {
    const parsed = AsnConvert.parse(publicKey, RSAPublicKey);

    return {
        n: bytesToNumberBE(new Uint8Array(parsed.modulus)),
        e: bytesToNumberBE(new Uint8Array(parsed.publicExponent))
    };
};

/** Extract public key from X.509 certificate and verify signature with RSA PKCS#1 */
export const rsaVerify = (cert: CertificateChoices, data: Uint8Array, signature: Uint8Array): boolean => {
    if (!cert.certificate) throw new Error('Invalid certificate. Missing "Certificate" in "CertificateChoices"');
    const publicKeyInfo = cert.certificate.tbsCertificate.subjectPublicKeyInfo;
    const algorithm = publicKeyInfo.algorithm;
    if (algorithm.algorithm !== id_rsaEncryption) throw new Error(`Invalid certificate. RSA certificate MUST use ${id_rsaEncryption} OID`);
    const signatureAlgorithm = cert.certificate.signatureAlgorithm.algorithm;
    const publicKey = convertSubjectPublicKey(publicKeyInfo.subjectPublicKey);

    // RSA-PSS Support
    if (signatureAlgorithm === id_RSASSA_PSS) return rsaPssVerify(cert).verify(publicKey, data, signature);

    // RSA-PKCS#1
    const pkcs1 = PKCS1_ALGORITHMS_BY_OID[signatureAlgorithm];
    if (!pkcs1) throw new Error(`Unsupported RSA Signature Algorithm OID: ${signatureAlgorithm}`);
    return pkcs1.verify(publicKey, data, signature);
};

/** RSA-PSS Verification */
function rsaPssVerify(cert: CertificateChoices) {
    const rawPssParams = cert.certificate!.signatureAlgorithm.parameters;
    if (!rawPssParams) throw new Error(`Missing RSA-PSS Parameters: ${cert.certificate!.signatureAlgorithm.algorithm}`);
    const parsePssParams = AsnConvert.parse(rawPssParams, RsaSaPssParams);

    // Get MGF1 hash algorithm
    if (!parsePssParams.maskGenAlgorithm.parameters) throw new Error(`Missing RSA-PSS MGF1 Algorithm: ${cert.certificate!.signatureAlgorithm.algorithm}`);
    const mgf1Hash = AsnConvert.parse(parsePssParams.maskGenAlgorithm.parameters, DigestAlgorithmIdentifier);
    const pssParams = {
        hashAlgorithm: HashHelper.resolve(parsePssParams.hashAlgorithm.algorithm),
        maskGenAlgorithm: RSAPaddingHelper.resolve(parsePssParams.maskGenAlgorithm.algorithm),
        maskGenHashAlgorithm: HashHelper.resolve(mgf1Hash.algorithm),
        saltLength: parsePssParams.saltLength
    };

    const rsaPSS = rsa.PSS(pssParams.hashAlgorithm, pssParams.maskGenAlgorithm(pssParams.maskGenHashAlgorithm), pssParams.saltLength);
    return rsaPSS;
}
