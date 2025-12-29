import { join as pjoin } from "path";
import { readFileSync } from "fs";
import { SOD, Interfaces } from "@li0ard/tsemrtd";
import { checkDGHashes, checkDSCCertificate, checkLDSHash, checkSODSignature } from "./crypto.js";
import { CSCAMasterList } from "@li0ard/icaopkd";
import { type CheckDGHashesInput, DataGroupDetailedResultCode } from "./types.js";
import { checkSODValidity, getCertificateCountry } from "./helpers/x509.js";
import chalk from 'chalk';

const args = process.argv.slice(2);
if(args.length == 0) {
    console.log("Usage: [node | bun] [dist/index.js | src/index.ts] <path to dump folder> <path to CSCA masterlist (.ml)>");
    process.exit();
}

const OK = chalk.greenBright("OK");
const ERROR = chalk.redBright("ERROR");
const SKIPPED = chalk.yellowBright("SKIPPED");

const step1 = (sod: Interfaces.DecodedSecurtyObjectOfDocument) => {
    const { signature } = checkSODValidity(sod);
    const result = checkLDSHash(sod);

    console.log(chalk.bold("Step 1. Verify LDS object hash:"));
    console.log(`- Algorithm: ${signature.digestAlgorithm.algorithm}`);
    console.log(`- Result: ${result ? OK : ERROR}\n`);
}

const step2 = (sod: Interfaces.DecodedSecurtyObjectOfDocument, dgs: CheckDGHashesInput) => {
    const result = checkDGHashes(sod, dgs);

    console.log(chalk.bold("Step 2. Verify datagroup hashes:"));
    console.log(`- Algorithm: ${sod.ldsObject.algorithm.algorithm}`);
    for(const dg of result.detailed)
        console.log(`- ${chalk.italic(`DG${dg.datagroup}`)}: ${dg.result == DataGroupDetailedResultCode.SUCCESS ? OK : (dg.result == DataGroupDetailedResultCode.SKIPPED ? SKIPPED : ERROR)}`);
    console.log(`- Result: ${result.result ? OK : ERROR}\n`);
}

const step3 = (sod: Interfaces.DecodedSecurtyObjectOfDocument) => {
    const { signature, dscCertificate } = checkSODValidity(sod);
    const result = checkSODSignature(sod);

    console.log(chalk.bold("Step 3. Verify SOD signature:"));
    console.log(`- Country: ${getCertificateCountry(dscCertificate)}`)
    console.log(`- Algorithm: ${signature.signatureAlgorithm.algorithm}`);
    console.log(`- Result: ${result ? OK : ERROR}\n`);
}

const step4 = (sod: Interfaces.DecodedSecurtyObjectOfDocument, pkd: CSCAMasterList) => {
    const { dscCertificate } = checkSODValidity(sod);
    const result = checkDSCCertificate(sod, pkd);

    console.log(chalk.bold("Step 4. Verify DSC certificate:"));
    console.log(`- Country: ${getCertificateCountry(dscCertificate)}`);
    console.log(`- Algorithm: ${dscCertificate.certificate?.signatureAlgorithm.algorithm}`);
    console.log(`- Result: ${result ? OK : ERROR}\n`);
}

const sod = SOD.load(readFileSync(pjoin(args[0], "EF_SOD.BIN")));
const pkd = CSCAMasterList.decode(readFileSync(args[1]));
const dgs: CheckDGHashesInput = {};

for(const dg of sod.ldsObject.hashes) {
    try {
        const dgFile = readFileSync(pjoin(args[0], `EF_DG${dg.number}.BIN`));
        dgs[dg.number] = dgFile;
    }
    catch(e) {}
}

step1(sod);
step2(sod, dgs);
step3(sod);
step4(sod, pkd);