pragma circom 2.2.3;

// Synthetic aggregate wiring only. All fixtures and the constructor's map are
// PUBLIC/NON-PRIVATE. No setup, proving, native profile or privacy claim.
// Authority templates are an exact prefix extraction; see ../EXTRACTION.json.
include "authority-template.circom";

template TwoOwnerAggregate() {
    // Exactly 2091 public input fields; the outer template has NO outputs.
    signal input anchor;
    signal input evaluationHeight;
    signal input testTag;
    signal input chainId;
    signal input poolId;
    signal input profileId;
    signal input roleId;
    signal input assetTag;
    signal input NF[2];
    signal input tuple[4][520];
    signal input feeTotal;

    // Private component slots. Signing secrets are not inputs. Child out[35]
    // (per-owner tuple digest, limbs and message) is never an outer output.
    signal input owner_nf[2];
    signal input owner_commitmentsOut[2][2];
    signal input owner_publicKeyBytes[2][2][32];
    signal input owner_signatureR8Bytes[2][2][32];
    signal input owner_signatureSBytes[2][32];
    signal input owner_nullifyingKey[2];
    signal input owner_inputRandom[2];
    signal input owner_inputSompi[2];
    signal input owner_leafIndex[2];
    signal input owner_siblingCM[2];
    signal input owner_outputNPK[2][2];
    signal input owner_valueOut[2][2];
    signal input owner_feeSompi[2];
    signal input owner_nonce[2];
    signal input owner_validFrom[2];
    signal input owner_validUntil[2];
    signal input owner_outputTuple[2][2][520];
    signal input U[2][2];
    signal input V[4][4];

    component authority[2];
    for (var i = 0; i < 2; i++) {
        authority[i] = AuthorityPredicate();
        authority[i].anchor <== anchor;
        authority[i].evaluationHeight <== evaluationHeight;
        authority[i].testTag <== testTag;
        authority[i].chainId <== chainId;
        authority[i].poolId <== poolId;
        authority[i].profileId <== profileId;
        authority[i].roleId <== roleId;
        authority[i].assetTag <== assetTag;
        authority[i].nf <== owner_nf[i];
        authority[i].nullifyingKey <== owner_nullifyingKey[i];
        authority[i].inputRandom <== owner_inputRandom[i];
        authority[i].inputSompi <== owner_inputSompi[i];
        authority[i].leafIndex <== owner_leafIndex[i];
        authority[i].siblingCM <== owner_siblingCM[i];
        authority[i].feeSompi <== owner_feeSompi[i];
        authority[i].nonce <== owner_nonce[i];
        authority[i].validFrom <== owner_validFrom[i];
        authority[i].validUntil <== owner_validUntil[i];
        for (var axis = 0; axis < 2; axis++) {
            for (var k = 0; k < 32; k++) {
                authority[i].publicKeyBytes[axis][k] <== owner_publicKeyBytes[i][axis][k];
                authority[i].signatureR8Bytes[axis][k] <== owner_signatureR8Bytes[i][axis][k];
            }
        }
        for (var k = 0; k < 32; k++) {
            authority[i].signatureSBytes[k] <== owner_signatureSBytes[i][k];
        }
        for (var j = 0; j < 2; j++) {
            authority[i].commitmentsOut[j] <== owner_commitmentsOut[i][j];
            authority[i].outputNPK[j] <== owner_outputNPK[i][j];
            authority[i].valueOut[j] <== owner_valueOut[i][j];
            for (var k = 0; k < 520; k++) {
                authority[i].outputTuple[j][k] <== owner_outputTuple[i][j][k];
            }
        }
    }

    // Boolean bijections, not arbitrary field-linear recombinations. Rows are
    // private records; columns are public rows. Both row and column sums matter.
    for (var i = 0; i < 2; i++) {
        var rowSum = 0;
        var columnSum = 0;
        for (var r = 0; r < 2; r++) {
            U[i][r]*(U[i][r]-1) === 0;
            rowSum += U[i][r];
            columnSum += U[r][i];
        }
        rowSum === 1;
        columnSum === 1;
    }
    for (var l = 0; l < 4; l++) {
        var rowSum = 0;
        var columnSum = 0;
        for (var r = 0; r < 4; r++) {
            V[l][r]*(V[l][r]-1) === 0;
            rowSum += V[l][r];
            columnSum += V[r][l];
        }
        rowSum === 1;
        columnSum === 1;
    }

    signal nfProduct[2][2];
    for (var i = 0; i < 2; i++) {
        for (var r = 0; r < 2; r++) {
            nfProduct[i][r] <== U[i][r]*owner_nf[i];
        }
    }
    for (var r = 0; r < 2; r++) {
        NF[r] === nfProduct[0][r] + nfProduct[1][r];
    }

    // Every one of the 520 approved bytes moves with the same private row.
    // Products are separate signals so each equation remains quadratic.
    signal tupleProduct[4][4][520];
    for (var l = 0; l < 4; l++) {
        for (var r = 0; r < 4; r++) {
            for (var k = 0; k < 520; k++) {
                tupleProduct[l][r][k] <== V[l][r]*owner_outputTuple[l\2][l%2][k];
            }
        }
    }
    for (var r = 0; r < 4; r++) {
        for (var k = 0; k < 520; k++) {
            var byteSum = 0;
            for (var l = 0; l < 4; l++) {
                byteSum += tupleProduct[l][r][k];
            }
            tuple[r][k] === byteSum;
        }
    }

    component equalNF = IsZero();
    equalNF.in <== NF[0]-NF[1];
    equalNF.out === 0;

    // Canonical CM bytes follow from child KpiCanonicalFieldBytes32 and the
    // Boolean whole-tuple bijection. This is ONLY within-batch distinctness.
    signal publicCM[4];
    for (var r = 0; r < 4; r++) {
        var cm = 0;
        for (var k = 0; k < 32; k++) {
            cm += tuple[r][k]*(2 ** (8*k));
        }
        publicCM[r] <== cm;
    }
    component equalCM[6];
    var pair = 0;
    for (var a = 0; a < 4; a++) {
        for (var b = a+1; b < 4; b++) {
            equalCM[pair] = IsZero();
            equalCM[pair].in <== publicCM[a]-publicCM[b];
            equalCM[pair].out === 0;
            pair++;
        }
    }

    // Child fees are u64, hence their exact integer sum is <2^65 << Fr.
    // No native MAX/floors, CV balance, Delta, spent set or effect binding.
    component feeRange = Num2Bits(65);
    feeRange.in <== feeTotal;
    feeTotal === owner_feeSompi[0] + owner_feeSompi[1];
}

component main {public [anchor, evaluationHeight, testTag, chainId, poolId,
    profileId, roleId, assetTag, NF, tuple, feeTotal]} = TwoOwnerAggregate();
