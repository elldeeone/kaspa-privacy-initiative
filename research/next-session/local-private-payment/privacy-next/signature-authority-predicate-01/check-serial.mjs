/*
    Copyright 2018 0KIMS association.

    This file is part of snarkJS.

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

import * as binFileUtils from "./tools/node_modules/@iden3/binfileutils/src/binfileutils.js";
import * as wtnsUtils from "./tools/node_modules/snarkjs/src/wtns_utils.js";
import { readR1csFd } from "./tools/node_modules/r1csfile/src/r1csfile.js";
import { Scalar } from "./tools/node_modules/snarkjs/node_modules/ffjavascript/main.js";
import * as curves from "./tools/node_modules/snarkjs/src/curves.js";

// Derived from selected Snarkjs 0.7.6 wtns_check.js, SHA256
// e150b29d1628a47e598ab7e85a46561f501c602d9599ad60b4923b5d6af4b456.
// Changes: source imports rebased only; both curve allocations singleThread=true;
// finally closes file/curve handles; explicit count/length/unit-wire format
// preconditions. Constraint arithmetic/loop are unchanged.
export default async function wtnsCheck(r1csFilename, wtnsFilename, logger) {
    let headerCurve, checkCurve, r1csHandle, witnessHandle;
    try {

    if (logger) logger.info("WITNESS CHECKING STARTED");

    // Read r1cs file
    if (logger) logger.info("> Reading r1cs file");
    const {
        fd: fdR1cs,
        sections: sectionsR1cs
    } = await binFileUtils.readBinFile(r1csFilename, "r1cs", 1, 1 << 22, 1 << 24);
    r1csHandle = fdR1cs;
    const r1cs = await readR1csFd(fdR1cs, sectionsR1cs, { loadConstraints: false, loadCustomGates: false, singleThread: true });
    headerCurve = r1cs.curve;

    // Read witness file
    if (logger) logger.info("> Reading witness file");
    const {
        fd: fdWtns,
        sections: wtnsSections
    } = await binFileUtils.readBinFile(wtnsFilename, "wtns", 2, 1 << 22, 1 << 24);
    witnessHandle = fdWtns;
    const wtnsHeader = await wtnsUtils.readHeader(fdWtns, wtnsSections);

    if (!Scalar.eq(r1cs.prime, wtnsHeader.q)) {
        throw new Error("Curve of the witness does not match the curve of the proving key");
    }
    if (wtnsHeader.n8 !== r1cs.n8 || wtnsHeader.nWitness !== r1cs.nVars) {
        throw new Error("Witness field width/count does not match selected R1CS");
    }

    const buffWitness = await binFileUtils.readSection(fdWtns, wtnsSections, 2);
    if (buffWitness.byteLength !== wtnsHeader.nWitness * wtnsHeader.n8) {
        throw new Error("Witness section length does not match header/count");
    }
    if (!Scalar.eq(Scalar.fromRprLE(buffWitness.slice(0, wtnsHeader.n8), 0, wtnsHeader.n8), Scalar.e(1))) {
        throw new Error("Witness constant wire must encode raw integer one");
    }
    await fdWtns.close();
    witnessHandle = null;

    const curve = await curves.getCurveFromR(r1cs.prime, {singleThread: true});
    checkCurve = curve;
    const Fr = curve.Fr;
    const sFr = Fr.n8;

    const bR1cs = await binFileUtils.readSection(fdR1cs, sectionsR1cs, 2);

    if (logger) {
        logger.info("----------------------------");
        logger.info("  WITNESS CHECK");
        logger.info(`  Curve:          ${r1cs.curve.name}`);
        logger.info(`  Vars (wires):   ${r1cs.nVars}`);
        logger.info(`  Outputs:        ${r1cs.nOutputs}`);
        logger.info(`  Public Inputs:  ${r1cs.nPubInputs}`);
        logger.info(`  Private Inputs: ${r1cs.nPrvInputs}`);
        logger.info(`  Labels:         ${r1cs.nLabels}`);
        logger.info(`  Constraints:    ${r1cs.nConstraints}`);
        logger.info(`  Custom Gates:   ${r1cs.useCustomGates}`);
        logger.info("----------------------------");
    }

    if (logger) logger.info("> Checking witness correctness");

    let bR1csPos = 0;
    let res = true;
    for (let i = 0; i < r1cs.nConstraints; i++) {
        if ((logger) && (i !== 0) && (i % 500000 === 0)) {
            logger.info(`··· processing r1cs constraints ${i}/${r1cs.nConstraints}`);
        }

        //Read the three linear combinations of the constraint where A * B - C = 0
        const lcA = readLC();
        const lcB = readLC();
        const lcC = readLC();

        // Evaluate the linear combinations
        const evalA = EvaluateLinearCombination(lcA);
        const evalB = EvaluateLinearCombination(lcB);
        const evalC = EvaluateLinearCombination(lcC);

        // Check that A * B - C == 0
        if (!Fr.eq(Fr.sub(Fr.mul(evalA, evalB), evalC), Fr.zero)) {
            logger.warn("··· aborting checking process at constraint " + i);
            res = false;
            break;
        }
    }

    await fdR1cs.close();
    r1csHandle = null;

    if (logger) {
        if (res) {
            logger.info("WITNESS IS CORRECT");
            logger.info("WITNESS CHECKING FINISHED SUCCESSFULLY");
        } else {
            logger.warn("WITNESS IS NOT CORRECT");
            logger.warn("WITNESS CHECKING FINISHED UNSUCCESSFULLY");
        }
    }

    return res;

    function EvaluateLinearCombination(lc) {
        let res = Fr.zero;

        const keys = Object.keys(lc);
        keys.forEach((signalId) => {
            const signalValue = getWitnessValue(signalId);
            const signalFactor = lc[signalId];

            res = Fr.add(res, Fr.mul(signalValue, signalFactor));
        });

        return res;
    }

    function readLC() {
        const lc = {};

        const buffUL32 = bR1cs.slice(bR1csPos, bR1csPos + 4);
        bR1csPos += 4;
        const buffUL32V = new DataView(buffUL32.buffer);
        const nIdx = buffUL32V.getUint32(0, true);

        const buff = bR1cs.slice(bR1csPos, bR1csPos + (4 + r1cs.n8) * nIdx);
        bR1csPos += (4 + r1cs.n8) * nIdx;
        const buffV = new DataView(buff.buffer);
        for (let i = 0; i < nIdx; i++) {
            const idx = buffV.getUint32(i * (4 + r1cs.n8), true);
            const val = r1cs.F.fromRprLE(buff, i * (4 + r1cs.n8) + 4);
            lc[idx] = val;
        }
        return lc;
    }

    function getWitnessValue(signalId) {
        return Fr.fromRprLE(buffWitness.slice(signalId * sFr, signalId * sFr + sFr));
    }
    } finally {
        if (witnessHandle) await witnessHandle.close();
        if (r1csHandle) await r1csHandle.close();
        if (checkCurve) await checkCurve.terminate();
        if (headerCurve && headerCurve !== checkCurve) await headerCurve.terminate();
    }
}
