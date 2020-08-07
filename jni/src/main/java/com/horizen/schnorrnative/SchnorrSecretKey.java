package com.horizen.schnorrnative;

import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class SchnorrSecretKey
{
    public static final int SECRET_KEY_LENGTH = 96;

    protected long secretKeyPointer;

    static {
        Library.load();
    }

    protected SchnorrSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    private static native int nativeGetSecretKeySize();

    private static native long nativeDeserializeSecretKey(byte[] secretKeyBytes);

    public static SchnorrSecretKey deserialize(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));

        long sk = nativeDeserializeSecretKey(secretKeyBytes);
        return sk != 0 ? new SchnorrSecretKey(sk) : null;
    }

    private native byte[] nativeSerializeSecretKey();

    public byte[] serializeSecretKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return nativeSerializeSecretKey();
    }

    private native void nativeFreeSecretKey();

    public void freeSecretKey() {
        if (secretKeyPointer != 0) {
            nativeFreeSecretKey();
            secretKeyPointer = 0;
        }
    }

    private native long nativeGetPublicKey();

    public SchnorrPublicKey getPublicKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return new SchnorrPublicKey(nativeGetPublicKey());
    }
}
