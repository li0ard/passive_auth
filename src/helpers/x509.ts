import type { DecodedSecurtyObjectOfDocument } from "@li0ard/tsemrtd/dist/consts/interfaces.js";
import { Attribute, type CertificateChoices, type CertificateSet } from "@peculiar/asn1-cms";
import { Curve } from "@peculiar/asn1-ecc";
import { AsnArray, AsnConvert, AsnIntegerBigIntConverter, AsnProp, AsnPropTypes, AsnType, AsnTypeTypes, OctetString } from "@peculiar/asn1-schema";

export const getCertificateCountry = (certificate: CertificateChoices): string => {
    if(!certificate.certificate) throw new Error("Invalid certificate. Missing \"Certificate\" in \"CertificateChoices\"");

    const countryRDN = certificate.certificate.tbsCertificate.subject.flatMap(rdn => rdn).find(attr => attr.type === "2.5.4.6");
    if(!countryRDN) throw new Error("Can't find country code RDN");

    return countryRDN.value.toString();
}

export const getCertificatesByCountryCode = (certificates: CertificateSet, countryCode: string): CertificateSet => {
    countryCode = countryCode.toUpperCase();
    return certificates.filter(certificate => {
        try {
            return getCertificateCountry(certificate) == countryCode.toUpperCase();
        } catch(e) { return false; }
    });
}

export const checkSODValidity = (sod: DecodedSecurtyObjectOfDocument) => {
    if(sod.signatures.length == 0) throw new Error("Missing signatures in SOD");
    const signature = sod.signatures[0];
    if(!signature.signedAttrs) throw new Error("Missing signed attributes in SOD");

    const messageDigestAttribute = signature.signedAttrs.find(i => i.attrType == "1.2.840.113549.1.9.4");
    if(!messageDigestAttribute) throw new Error("Missing message digest attribute in SOD");
    if (messageDigestAttribute.attrValues.length === 0) throw new Error("Empty message digest attribute value");

    if(sod.certificates.length == 0) throw new Error("Missing certificates in SOD");
    const dscCertificate = sod.certificates[0];
    if(!dscCertificate.certificate) throw new Error("Invalid certificate. Missing \"Certificate\" in \"CertificateChoices\"");

    return {
        sodObjectHash: new Uint8Array(AsnConvert.parse(messageDigestAttribute.attrValues[0], OctetString).buffer),
        signature, dscCertificate
    }
}

/** ASN1 schema of explicit PKCS7 signed attributes */
@AsnType({ type: AsnTypeTypes.Set, itemType: Attribute })
export class SignedAttributesExplicit extends AsnArray<Attribute> {}

// Little bit simplified schemas from `@peculiar/asn1-ecc`
export class FieldID {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    fieldType!: string;
  
    // Change #1: Here's a number, because we always use `prime-field` (1.2.840.10045.1.1)
    @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
    parameters!: bigint;
}

export class SpecifiedECDomain {
    @AsnProp({ type: AsnPropTypes.Integer })
    version!: number;
  
    @AsnProp({ type: FieldID })
    fieldID!: FieldID;
  
    @AsnProp({ type: Curve })
    curve!: Curve;
  
    @AsnProp({ type: AsnPropTypes.OctetString })
    base!: ArrayBuffer;
  
    // Change #2: Instant conversion of ASN.1 INTEGER to bigint
    @AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerBigIntConverter })
    order!: bigint;
  
    // Change #3: Standard says "...MUST include the optional co-factor."
    @AsnProp({ type: AsnPropTypes.Integer, optional: true, converter: AsnIntegerBigIntConverter })
    cofactor!: bigint;
}