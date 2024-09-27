import { PKD, SOD } from "@li0ard/tsemrtd"
import { type CertificateChoices } from "@peculiar/asn1-cms"
import { AsnConvert, OctetString } from "@peculiar/asn1-schema"
import { join as pjoin } from "path"
import fs from "fs"
import { SignedAttributes, getCertsByCountryCode, hash, verify } from "./crypto"

if(process.argv.length != 4) {
    console.log("Usage: bun index.ts <path to passport> <path to icao ml>")
    process.exit(0)
}

let path = process.argv[2]
let ml = process.argv[3]

let file = fs.readFileSync(pjoin(path, "EF_SOD.BIN"))
let sod = SOD.load(file)
let pkd = PKD.load(fs.readFileSync(ml))

console.log(`Passive Authentication (PA):`)
console.log(`- Step 1. Verify LDS object hash:`)
let sodObjectHash = Buffer.from(AsnConvert.parse(sod.signatures[0].signedAttrs?.filter(i => i.attrType == "1.2.840.113549.1.9.4")[0].attrValues[0] as ArrayBuffer, OctetString).buffer)
let sodObjectResult = sodObjectHash.equals(hash(sod.signatures[0].digestAlgorithm.algorithm, Buffer.from(AsnConvert.serialize(sod.ldsObject))))
console.log(`  * LDS object hash: ${sodObjectResult ? "OK" : "Failed"}`)

console.log(`- Step 2. Verify datagroup hashes:`)
for(let i of sod.ldsObject.hashes) {
    try {
        let dgFile = fs.readFileSync(pjoin(path, `EF_DG${i.number}.BIN`))
        let dgHashResult = hash(sod.ldsObject.algorithm.algorithm, dgFile).equals(i.hash)
        console.log(`  * EF_DG${i.number}.BIN - ${dgHashResult ? "OK" : "Failed"}`)
    } catch(e) {
        if((e as Error).name == "ENOENT") {
            console.log(`  * EF_DG${i.number}.BIN not found. Skip...`)
        }
        else {
            console.error(e)
        }
    }
}

console.log(`- Step 3. Verify SOD signature`)
let dscCert = sod.certificates?.at(0) as CertificateChoices
let sodResult = verify(dscCert, Buffer.from(AsnConvert.serialize(new SignedAttributes(sod.signatures.at(0)?.signedAttrs))), Buffer.from(sod.signatures.at(0)?.signature.buffer as ArrayBuffer))
console.log(`  * SOD signature: ${sodResult ? "OK" : "Failed"}`)

console.log(`- Step 4. Verify certificate`)
let dscResult = false;
let dscCertSig = Buffer.from(dscCert?.certificate?.signatureValue as ArrayBuffer)
let dscCertData = Buffer.from(AsnConvert.serialize(dscCert?.certificate?.tbsCertificate))

let countryCode = dscCert.certificate?.tbsCertificate.subject.filter(j => j.filter(i => i.type == "2.5.4.6")[0])[0][0].value.printableString as string
for(let i of getCertsByCountryCode(pkd.certificates, countryCode)) {
    if(verify(i, dscCertData, dscCertSig)) {
        dscResult = true
        break;
    }
}
console.log(`  * DSC certificate - ${dscResult ? "OK" : "Failed"}`)