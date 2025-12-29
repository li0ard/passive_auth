import type { DecodedSecurtyObjectOfDocument } from "@li0ard/tsemrtd/dist/consts/interfaces";
import { equalBytes } from "@noble/curves/utils.js";
import type { CertificateChoices } from "@peculiar/asn1-cms";
import { AsnConvert } from "@peculiar/asn1-schema";
import { DataGroupDetailedResultCode, type CheckDGHashesInput, type CheckDGHashesResult, type DataGroupDetailedResult } from "./types.js";
import { HashHelper } from "./helpers/hash.js";
import type { CSCAMasterList } from "@li0ard/icaopkd";
import { checkSODValidity, getCertificateCountry, getCertificatesByCountryCode, SignedAttributesExplicit } from "./helpers/x509.js";
import { ecdsaVerify } from "./ecdsa/index.js";
import { rsaVerify } from "./rsa/index.js";
import { rsaEncryption } from "@peculiar/asn1-rsa";

const verify = (certificate: CertificateChoices, data: Uint8Array, signature: Uint8Array): boolean => {
    if(!certificate.certificate) throw new Error("Invalid certificate. Missing \"Certificate\" in \"CertificateChoices\"");
    const isRSA = certificate.certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.isEqual(rsaEncryption);

    return isRSA ? rsaVerify(certificate, data, signature) : ecdsaVerify(certificate, data, signature);
}

export const checkLDSHash = (sod: DecodedSecurtyObjectOfDocument): boolean => {
    const { sodObjectHash, signature } = checkSODValidity(sod);
    const ldsObjectSerialized = new Uint8Array(AsnConvert.serialize(sod.ldsObject));

    return equalBytes(HashHelper.hash(signature.digestAlgorithm.algorithm, ldsObjectSerialized), sodObjectHash);
}

export const checkDGHashes = (sod: DecodedSecurtyObjectOfDocument, dgs: CheckDGHashesInput): CheckDGHashesResult => {
    let allOk = true;
    const detailedResults: DataGroupDetailedResult[] = [];
    const hashAlgorithm = HashHelper.resolve(sod.ldsObject.algorithm.algorithm);
    for(const i of sod.ldsObject.hashes) {
        const dgFile = dgs[i.number];
        if(!dgFile) {
            detailedResults.push({ datagroup: i.number, result: DataGroupDetailedResultCode.SKIPPED });
            continue;
        }
        const result = equalBytes(hashAlgorithm(dgFile), i.hash)
            ? DataGroupDetailedResultCode.SUCCESS
            : DataGroupDetailedResultCode.ERROR;
        if (result === DataGroupDetailedResultCode.ERROR) allOk = false;

        detailedResults.push({ datagroup: i.number, result });
    }
    
    return { result: allOk, detailed: detailedResults }
}

export const checkSODSignature = (sod: DecodedSecurtyObjectOfDocument): boolean => {
    const { dscCertificate, signature } = checkSODValidity(sod);
    const signedAttributesSerialized = new Uint8Array(AsnConvert.serialize(new SignedAttributesExplicit(signature.signedAttrs)));

    return verify(dscCertificate, signedAttributesSerialized, new Uint8Array(signature.signature.buffer));
}

export const checkDSCCertificate = (sod: DecodedSecurtyObjectOfDocument, masterList: CSCAMasterList): boolean => {
    const { dscCertificate } = checkSODValidity(sod);
    const dscCertificateSignature = new Uint8Array(dscCertificate.certificate!.signatureValue);
    const dscCertificateDataSerialized = new Uint8Array(AsnConvert.serialize(dscCertificate.certificate!.tbsCertificate));

    const cscaCertificates = getCertificatesByCountryCode(masterList.certificates, getCertificateCountry(dscCertificate));
    for(const certificate of cscaCertificates) {
        try {
            if(verify(certificate, dscCertificateDataSerialized, dscCertificateSignature)) return true;
        } catch(e) { console.log(`Failed to verify with CSCA certificate: ${(e as Error).message}`); }
    }
    
    return false;
}