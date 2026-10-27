pragma circom 2.2.3;

// Offline signature-authority predicate only. This is not a native/profile,
// aggregate, privacy or malicious-MPC circuit. No spending signing key input.
// Frozen plan: 42900a915b5e61078597cef42ad351819605276db20bd4f96e661816af757ac2.
// Circomlib 2.0.5 / cff5ab6288b55ef23602221694a6a38a0239dcc0.
include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/sha256/sha256.circom";

// Bind every byte bit to the unique field representative. Num2Bits_strict
// rejects values >= Fr modulus; the remaining two bits are explicitly zero.
template KpiCanonicalFieldBytes32() {
    signal input bytes[32];
    signal output value;
    component byteBits[32];
    component strictBits = Num2Bits_strict();
    var encoded = 0;
    for (var i = 0; i < 32; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== bytes[i];
        encoded += bytes[i] * (2 ** (8*i));
    }
    value <== encoded;
    strictBits.in <== value;
    for (var k = 0; k < 254; k++) {
        byteBits[k\8].out[k%8] === strictBits.out[k];
    }
    byteBits[31].out[6] === 0;
    byteBits[31].out[7] === 0;
}

// S has an unsigned 253-bit encoding. The mandatory upstream EdDSA verifier
// separately enforces S < Q, so the same scalar cannot have a byte alias.
template KpiCanonicalScalarBytes32() {
    signal input bytes[32];
    signal output value;
    component byteBits[32];
    var encoded = 0;
    for (var i = 0; i < 32; i++) {
        byteBits[i] = Num2Bits(8);
        byteBits[i].in <== bytes[i];
        encoded += bytes[i] * (2 ** (8*i));
    }
    byteBits[31].out[5] === 0;
    byteBits[31].out[6] === 0;
    byteBits[31].out[7] === 0;
    value <== encoded;
}

// BabyAdd's hinted divisions are backed by equations in the pinned gadget.
// Explicit inverses here rule out zero-denominator unconstrained branches.
template KpiAddDenominatorsNonzero() {
    signal input p[2];
    signal input q[2];
    signal beta;
    signal gamma;
    signal tau;
    signal plus;
    signal minus;
    signal plusInv;
    signal minusInv;
    beta <== p[0]*q[1];
    gamma <== p[1]*q[0];
    tau <== beta*gamma;
    plus <== 1 + 168696*tau;
    minus <== 1 - 168696*tau;
    plusInv <-- plus != 0 ? 1/plus : 0;
    minusInv <-- minus != 0 ? 1/minus : 0;
    plus*plusInv === 1;
    minus*minusInv === 1;
}

template KpiCheckedBabyAdd() {
    signal input p[2];
    signal input q[2];
    signal output out[2];
    component pCurve = BabyCheck();
    component qCurve = BabyCheck();
    component outCurve = BabyCheck();
    component den = KpiAddDenominatorsNonzero();
    component add = BabyAdd();
    pCurve.x <== p[0];
    pCurve.y <== p[1];
    qCurve.x <== q[0];
    qCurve.y <== q[1];
    for (var i = 0; i < 2; i++) {
        den.p[i] <== p[i];
        den.q[i] <== q[i];
    }
    add.x1 <== p[0];
    add.y1 <== p[1];
    add.x2 <== q[0];
    add.y2 <== q[1];
    out[0] <== add.xout;
    out[1] <== add.yout;
    outCurve.x <== out[0];
    outCurve.y <== out[1];
}

template KpiCheckedBabyDbl() {
    signal input p[2];
    signal output out[2];
    component pCurve = BabyCheck();
    component outCurve = BabyCheck();
    component den = KpiAddDenominatorsNonzero();
    component dbl = BabyDbl();
    pCurve.x <== p[0];
    pCurve.y <== p[1];
    for (var i = 0; i < 2; i++) {
        den.p[i] <== p[i];
        den.q[i] <== p[i];
    }
    dbl.x <== p[0];
    dbl.y <== p[1];
    out[0] <== dbl.xout;
    out[1] <== dbl.yout;
    outCurve.x <== out[0];
    outCurve.y <== out[1];
}

// Source-backed constant scalar test: on-curve P, [Q]P=(0,1), P!=(0,1).
// This uses the same Q criterion as circomlibjs BabyJub.inSubgroup.
// EscalarMulAny is deliberately NOT used to validate its own subgroup
// precondition. Leading zero scalar bits just double the identity.
template KpiPrimeSubgroupNonidentity() {
    signal input p[2];
    var Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    var nAdds = 0;
    for (var i = 0; i < 253; i++) {
        nAdds += (Q >> i) & 1;
    }
    component curve = BabyCheck();
    component xZero = IsZero();
    component yOne = IsZero();
    component doubles[253];
    component adds[nAdds];
    signal acc[254][2];
    curve.x <== p[0];
    curve.y <== p[1];
    xZero.in <== p[0];
    yOne.in <== p[1]-1;
    xZero.out*yOne.out === 0;
    acc[0][0] <== 0;
    acc[0][1] <== 1;
    var addIndex = 0;
    for (var i = 0; i < 253; i++) {
        doubles[i] = KpiCheckedBabyDbl();
        doubles[i].p[0] <== acc[i][0];
        doubles[i].p[1] <== acc[i][1];
        if (((Q >> (252-i)) & 1) == 1) {
            adds[addIndex] = KpiCheckedBabyAdd();
            adds[addIndex].p[0] <== doubles[i].out[0];
            adds[addIndex].p[1] <== doubles[i].out[1];
            adds[addIndex].q[0] <== p[0];
            adds[addIndex].q[1] <== p[1];
            acc[i+1][0] <== adds[addIndex].out[0];
            acc[i+1][1] <== adds[addIndex].out[1];
            addIndex++;
        } else {
            acc[i+1][0] <== doubles[i].out[0];
            acc[i+1][1] <== doubles[i].out[1];
        }
    }
    acc[253][0] === 0;
    acc[253][1] === 1;
}

template AuthorityPredicate() {
    // Only output array: stable output witness positions 1..35.
    // [0..31] digest bytes, [32/33] LE128 limbs, [34] signed message M.
    signal output out[35];
    signal input anchor;
    signal input nf;
    signal input commitmentsOut[2];
    signal input evaluationHeight;
    signal input testTag;
    signal input chainId;
    signal input poolId;
    signal input profileId;
    signal input roleId;
    signal input assetTag;
    signal input publicKeyBytes[2][32];
    signal input signatureR8Bytes[2][32];
    signal input signatureSBytes[32];
    signal input nullifyingKey;
    signal input inputRandom;
    signal input inputSompi;
    signal input leafIndex;
    signal input siblingCM;
    signal input outputNPK[2];
    signal input valueOut[2];
    signal input feeSompi;
    signal input nonce;
    signal input validFrom;
    signal input validUntil;
    signal input outputTuple[2][520];

    // Public synthetic context/amount integers; no current-domain semantics.
    signal u64Values[14];
    component u64Ranges[14];
    u64Values[0] <== testTag;
    u64Values[1] <== chainId;
    u64Values[2] <== poolId;
    u64Values[3] <== profileId;
    u64Values[4] <== roleId;
    u64Values[5] <== assetTag;
    u64Values[6] <== inputSompi;
    u64Values[7] <== valueOut[0];
    u64Values[8] <== valueOut[1];
    u64Values[9] <== feeSompi;
    u64Values[10] <== nonce;
    u64Values[11] <== validFrom;
    u64Values[12] <== validUntil;
    u64Values[13] <== evaluationHeight;
    for (var i = 0; i < 14; i++) {
        u64Ranges[i] = Num2Bits(64);
        u64Ranges[i].in <== u64Values[i];
    }
    // All four values are u64; the RHS is <3*2^64, far below Fr modulus.
    inputSompi === valueOut[0] + valueOut[1] + feeSompi;
    leafIndex*(leafIndex-1) === 0;
    component lowerHeight = LessEqThan(64);
    component upperHeight = LessEqThan(64);
    lowerHeight.in[0] <== validFrom;
    lowerHeight.in[1] <== evaluationHeight;
    lowerHeight.out === 1;
    upperHeight.in[0] <== evaluationHeight;
    upperHeight.in[1] <== validUntil;
    upperHeight.out === 1;

    component pk[2];
    component r8[2];
    component s = KpiCanonicalScalarBytes32();
    for (var axis = 0; axis < 2; axis++) {
        pk[axis] = KpiCanonicalFieldBytes32();
        r8[axis] = KpiCanonicalFieldBytes32();
        for (var k = 0; k < 32; k++) {
            pk[axis].bytes[k] <== publicKeyBytes[axis][k];
            r8[axis].bytes[k] <== signatureR8Bytes[axis][k];
        }
    }
    for (var k = 0; k < 32; k++) {
        s.bytes[k] <== signatureSBytes[k];
    }
    component pkSubgroup = KpiPrimeSubgroupNonidentity();
    component r8Subgroup = KpiPrimeSubgroupNonidentity();
    for (var axis = 0; axis < 2; axis++) {
        pkSubgroup.p[axis] <== pk[axis].value;
        r8Subgroup.p[axis] <== r8[axis].value;
    }

    // RAILGUN source pattern: signature PK and independent NF key are both
    // committed into the consumed note. No signing secret is a circuit input.
    component masterPK = Poseidon(3);
    masterPK.inputs[0] <== pk[0].value;
    masterPK.inputs[1] <== pk[1].value;
    masterPK.inputs[2] <== nullifyingKey;
    component inputNPK = Poseidon(2);
    inputNPK.inputs[0] <== masterPK.out;
    inputNPK.inputs[1] <== inputRandom;
    component inputCM = Poseidon(3);
    inputCM.inputs[0] <== inputNPK.out;
    inputCM.inputs[1] <== assetTag;
    inputCM.inputs[2] <== inputSompi;
    signal left;
    signal right;
    left <== inputCM.out + leafIndex*(siblingCM-inputCM.out);
    right <== siblingCM + leafIndex*(inputCM.out-siblingCM);
    component root = Poseidon(2);
    root.inputs[0] <== left;
    root.inputs[1] <== right;
    root.out === anchor;
    component nullifier = Poseidon(2);
    nullifier.inputs[0] <== nullifyingKey;
    nullifier.inputs[1] <== leafIndex;
    nullifier.out === nf;
    component outputCM[2];
    component cmBytes[2];
    for (var j = 0; j < 2; j++) {
        outputCM[j] = Poseidon(3);
        outputCM[j].inputs[0] <== outputNPK[j];
        outputCM[j].inputs[1] <== assetTag;
        outputCM[j].inputs[2] <== valueOut[j];
        outputCM[j].out === commitmentsOut[j];
        cmBytes[j] = KpiCanonicalFieldBytes32();
        for (var k = 0; k < 32; k++) {
            cmBytes[j].bytes[k] <== outputTuple[j][k];
        }
        cmBytes[j].value === commitmentsOut[j];
    }

    // Complete tuples: CM32|CV64|CF264|cfh32|proof128. Their validity beyond
    // authorization/byte ranges is UNIMPLEMENTED. All bytes are SHA-bound.
    component tupleBits[2][520];
    component fullTupleHash = Sha256(8384);
    var prefix[8] = [75,80,73,65,85,84,48,49]; // ASCII KPIAUT01.
    for (var k = 0; k < 8; k++) {
        for (var bit = 0; bit < 8; bit++) {
            fullTupleHash.in[8*k+bit] <== (prefix[k] >> (7-bit)) & 1;
        }
    }
    for (var j = 0; j < 2; j++) {
        for (var k = 0; k < 520; k++) {
            tupleBits[j][k] = Num2Bits(8);
            tupleBits[j][k].in <== outputTuple[j][k];
            for (var bit = 0; bit < 8; bit++) {
                fullTupleHash.in[64+8*(520*j+k)+bit] <== tupleBits[j][k].out[7-bit];
            }
        }
    }
    for (var k = 0; k < 32; k++) {
        var digestByte = 0;
        for (var bit = 0; bit < 8; bit++) {
            digestByte += fullTupleHash.out[8*k+bit]*(2 ** (7-bit));
        }
        out[k] <== digestByte;
    }
    var digestLo = 0;
    var digestHi = 0;
    for (var k = 0; k < 16; k++) {
        digestLo += out[k]*(2 ** (8*k));
        digestHi += out[16+k]*(2 ** (8*k));
    }
    out[32] <== digestLo;
    out[33] <== digestHi;
    component limbLo = Num2Bits(128);
    component limbHi = Num2Bits(128);
    limbLo.in <== out[32];
    limbHi.in <== out[33];

    component bound = Poseidon(12);
    bound.inputs[0] <== testTag;
    bound.inputs[1] <== chainId;
    bound.inputs[2] <== poolId;
    bound.inputs[3] <== profileId;
    bound.inputs[4] <== roleId;
    bound.inputs[5] <== nonce;
    bound.inputs[6] <== validFrom;
    bound.inputs[7] <== validUntil;
    bound.inputs[8] <== feeSompi;
    bound.inputs[9] <== out[32];
    bound.inputs[10] <== out[33];
    bound.inputs[11] <== 2;
    component message = Poseidon(5);
    message.inputs[0] <== anchor;
    message.inputs[1] <== bound.out;
    message.inputs[2] <== nf;
    message.inputs[3] <== commitmentsOut[0];
    message.inputs[4] <== commitmentsOut[1];
    out[34] <== message.out;

    // Actual pinned verifier, always enabled; S<Q is enforced inside it.
    component signature = EdDSAPoseidonVerifier();
    signature.enabled <== 1;
    signature.Ax <== pk[0].value;
    signature.Ay <== pk[1].value;
    signature.R8x <== r8[0].value;
    signature.R8y <== r8[1].value;
    signature.S <== s.value;
    signature.M <== message.out;
}

component main {public [anchor, nf, commitmentsOut, evaluationHeight,
    testTag, chainId, poolId, profileId, roleId, assetTag]} = AuthorityPredicate();
