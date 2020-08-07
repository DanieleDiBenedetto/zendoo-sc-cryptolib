package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class SchnorrKeyPair {
    public long secretKey;
    public long publicKey;

    static {
        Library.load();
    }

    public SchnorrKeyPair(long secretKey, long publicKey) {
        this.secretKey = secretKey;
        this.publicKey = publicKey;
    }

    public SchnorrKeyPair(long secretKey) {
        this.secretKey = secretKey;
        this.publicKey = new SchnorrSecretKey(this.secretKey).getPublicKey().publicKeyPointer;
    }

    public SchnorrKeyPair(SchnorrSecretKey sk) {
        this.secretKey = sk.secretKeyPointer;
        this.publicKey = sk.getPublicKey().publicKeyPointer;
    }

    private static native SchnorrKeyPair nativeGenerate();

    public static SchnorrKeyPair generate() {

        return nativeGenerate();
    }

    private native long nativeSignMessage(FieldElement message);

    public SchnorrSignature signMessage(FieldElement message) {

        long sig = nativeSignMessage(message);
        return sig != 0 ? new SchnorrSignature(sig) : null;
    }

    public SchnorrSecretKey getSecretKey() {
        return new SchnorrSecretKey(this.secretKey);
    }

    public SchnorrPublicKey getPublicKey() {
        return new SchnorrPublicKey(this.publicKey);
    }
}
