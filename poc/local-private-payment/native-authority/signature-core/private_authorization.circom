pragma circom 2.0.6;
// SOURCE ONLY. Component public edges are INTERNALIZED in the final joined CS.
// Never publish a component proof or treat this as an accepted Native profile.
include "../vendor/circomlib/circuits/eddsaposeidon.circom";
include "../vendor/circomlib/circuits/babyjub.circom";
include "../vendor/circomlib/circuits/bitify.circom";
include "../vendor/circomlib/circuits/comparators.circom";

template CanonicalCoordinate() {
 signal input bytes[32]; signal output coordinate;
 component bb[32]; component decode=Bits2Num_strict();
 for(var i=0;i<32;i++){bb[i]=Num2Bits(8);bb[i].in<==bytes[i];}
 for(var i=0;i<254;i++){decode.in[i]<==bb[i\8].out[i%8];}
 bb[31].out[6]===0;bb[31].out[7]===0;coordinate<==decode.out;
}

template GuardedCofactorImage() {
 signal input preimage[2];signal input point[2];
 signal x[4];signal y[4];signal xy[3];signal tau[3];
 component checks[4];component dbl[3];component dp[3];component dm[3];
 x[0]<==preimage[0];y[0]<==preimage[1];
 for(var i=0;i<3;i++){
  checks[i]=BabyCheck();checks[i].x<==x[i];checks[i].y<==y[i];
  xy[i]<==x[i]*y[i];tau[i]<==xy[i]*xy[i];
  dp[i]=IsZero();dp[i].in<==1+168696*tau[i];dp[i].out===0;
  dm[i]=IsZero();dm[i].in<==1-168696*tau[i];dm[i].out===0;
  dbl[i]=BabyDbl();dbl[i].x<==x[i];dbl[i].y<==y[i];
  x[i+1]<==dbl[i].xout;y[i+1]<==dbl[i].yout;
 }
 checks[3]=BabyCheck();checks[3].x<==x[3];checks[3].y<==y[3];
 x[3]===point[0];y[3]===point[1];
 component targetCheck=BabyCheck();targetCheck.x<==point[0];targetCheck.y<==point[1];
 component nonidentity=IsZero();nonidentity.in<==point[0];nonidentity.out===0;
}

template NativeAuthSignature() {
 signal input digestLimbs[2];signal input ownerKeyBytes[64];
 signal input sigR8[2];signal input sigS;
 signal input preimageA[2];signal input preimageR8[2];
 component digestRange[2];component message=Poseidon(2);
 for(var i=0;i<2;i++){digestRange[i]=Num2Bits(128);digestRange[i].in<==digestLimbs[i];message.inputs[i]<==digestLimbs[i];}
 component ax=CanonicalCoordinate();component ay=CanonicalCoordinate();
 for(var i=0;i<32;i++){ax.bytes[i]<==ownerKeyBytes[i];ay.bytes[i]<==ownerKeyBytes[32+i];}
 component admitA=GuardedCofactorImage();admitA.preimage[0]<==preimageA[0];admitA.preimage[1]<==preimageA[1];admitA.point[0]<==ax.coordinate;admitA.point[1]<==ay.coordinate;
 component admitR=GuardedCofactorImage();admitR.preimage[0]<==preimageR8[0];admitR.preimage[1]<==preimageR8[1];admitR.point[0]<==sigR8[0];admitR.point[1]<==sigR8[1];
 component verifier=EdDSAPoseidonVerifier();verifier.enabled<==1;
 verifier.Ax<==ax.coordinate;verifier.Ay<==ay.coordinate;verifier.R8x<==sigR8[0];verifier.R8y<==sigR8[1];verifier.S<==sigS;verifier.M<==message.out;
}
component main {public [digestLimbs,ownerKeyBytes]}=NativeAuthSignature();
