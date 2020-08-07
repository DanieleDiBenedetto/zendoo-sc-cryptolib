package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFSecretKey
{
    public static final int SECRET_KEY_LENGTH = 96;

    protected long secretKeyPointer;

    static {
        Library.load();
    }

    protected VRFSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    private static native int nativeGetSecretKeySize();

    private static native long nativeDeserializeSecretKey(byte[] secretKeyBytes);

    public static VRFSecretKey deserialize(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));

        long sk = nativeDeserializeSecretKey(secretKeyBytes);
        return sk != 0 ? new VRFSecretKey(sk) : null;
    }

    private native byte[] nativeSerializeSecretKey();

    public byte[] serializeSecretKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return nativeSerializeSecretKey();
    }

    private native void nativeFreeSecretKey(long secretKeyPointer);

    public void freeSecretKey() {
        if (secretKeyPointer != 0) {
            nativeFreeSecretKey(secretKeyPointer);
            secretKeyPointer = 0;
        }
    }

    private native long nativeGetPublicKey();

    public VRFPublicKey getPublicKey() {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key was freed.");

        return new VRFPublicKey(nativeGetPublicKey());
    }
}
