package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;

import java.util.List;

public class NaiveThresholdSigProof {

    private static native long nativeGetConstant(SchnorrPublicKey[] schnorrPublicKeys, long threshold);

    public static FieldElement getConstant(List<SchnorrPublicKey> schnorrPublicKeys, long threshold) {
        long constant = nativeGetConstant(schnorrPublicKeys.toArray(new SchnorrPublicKey[0]), threshold);
        return constant != 0 ? new FieldElement(constant) : null;
    }

    private static native long nativeCreateMsgToSign(BackwardTransfer[] bt,
                                                             byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash);

    public static FieldElement createMsgToSign(BackwardTransfer[] bt,
                                               byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash) {
        long msg = nativeCreateMsgToSign(bt, endEpochBlockHash, prevEndEpochBlockHash);
        return msg != 0 ? new FieldElement(msg) : null;
    }

    private static native CreateProofResult nativeCreateProof(BackwardTransfer[] bt,
                                                   byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                                   SchnorrSignature[] schnorrSignatures, SchnorrPublicKey[] schnorrPublicKeys,
                                                   long threshold, String provingKeyPath);

    public static CreateProofResult createProof(List<BackwardTransfer> btList,
                                     byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                     List<SchnorrSignature> schnorrSignatureList, List<SchnorrPublicKey> schnorrPublicKeyList,
                                     long threshold, String provingKeyPath) {
       return   nativeCreateProof(btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrSignatureList.toArray(new SchnorrSignature[0]), schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath);
    }

    private static native boolean nativeVerifyProof(BackwardTransfer[] btList,
                                      byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                      FieldElement constant, long quality, byte[] proof, String verificationKeyPath);

    public static boolean verifyProof(List<BackwardTransfer> btList,
                                      byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                      FieldElement constant, long quality, byte[] proof, String verificationKeyPath){
        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]),
                endEpochBlockHash, prevEndEpochBlockHash,
                constant, quality, proof, verificationKeyPath);
    }
}
