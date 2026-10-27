pragma circom 2.2.3;

// Source-only companion for the frozen padding-boundary checks.
// No signature, protocol/profile or native-privacy predicate is implemented.
// Circomlib 2.0.5 / cff5ab6288b55ef23602221694a6a38a0239dcc0.
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";

template KpiGoldenDigest(nBytes) {
    assert(nBytes <= 64);
    signal input bytes[64];
    // Standard digest bytes, then LE128(first16) and LE128(last16).
    signal output out[34];
    component byteBits[64];
    component hash = Sha256(8*nBytes);
    for (var k = 0; k < 64; k++) {
        byteBits[k] = Num2Bits(8);
        byteBits[k].in <== bytes[k];
        if (k < nBytes) {
            for (var bit = 0; bit < 8; bit++) {
                hash.in[8*k+bit] <== byteBits[k].out[7-bit];
            }
        }
    }
    for (var k = 0; k < 32; k++) {
        var digestByte = 0;
        for (var bit = 0; bit < 8; bit++) {
            digestByte += hash.out[8*k+bit]*(2 ** (7-bit));
        }
        out[k] <== digestByte;
    }
    var low = 0;
    var high = 0;
    for (var k = 0; k < 16; k++) {
        low += out[k]*(2 ** (8*k));
        high += out[16+k]*(2 ** (8*k));
    }
    out[32] <== low;
    out[33] <== high;
    component lowBits = Num2Bits(128);
    component highBits = Num2Bits(128);
    lowBits.in <== out[32];
    highBits.in <== out[33];
}

template KpiHashPaddingGoldens() {
    signal input bytes[64];
    // Rows correspond to the first 55, 56, 63 and 64 input bytes.
    // These fixed sizes use 1+2+2+2 = 7 SHA256 compression blocks.
    signal output out[4][34];
    var lengths[4] = [55,56,63,64];
    component cases[4];
    for (var i = 0; i < 4; i++) {
        cases[i] = KpiGoldenDigest(lengths[i]);
        for (var k = 0; k < 64; k++) {
            cases[i].bytes[k] <== bytes[k];
        }
        for (var k = 0; k < 34; k++) {
            out[i][k] <== cases[i].out[k];
        }
    }
}

component main = KpiHashPaddingGoldens();
