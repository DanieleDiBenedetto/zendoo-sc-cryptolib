package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;


public class VRFKeyPair {
    private long secretKey;
    private long publicKey;

    static {
        Library.load();
    }

    public VRFKeyPair(long secretKey, long publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public VRFKeyPair(long secretKey) {
        this.secretKey = secretKey;
        this.publicKey = new VRFSecretKey(this.secretKey).getPublicKey().publicKeyPointer;
    }

    public VRFKeyPair(VRFSecretKey sk) {
        this.secretKey = sk.secretKeyPointer;
        this.publicKey = sk.getPublicKey().publicKeyPointer;
    }

    private static native VRFKeyPair nativeGenerate();

    public static VRFKeyPair generate() {

        return nativeGenerate();
    }

    private native VRFProveResult nativeProve(FieldElement message);

    public VRFProveResult prove(FieldElement message) {
        VRFProveResult res = nativeProve(message);
        return (res.vrfProof != 0 && res.vrfOutput != 0) ? res : null;
    }

    public VRFSecretKey getSecretKey() {
        return new VRFSecretKey(this.secretKey);
    }

    public VRFPublicKey getPublicKey() {
        return new VRFPublicKey(this.publicKey);
    }
}