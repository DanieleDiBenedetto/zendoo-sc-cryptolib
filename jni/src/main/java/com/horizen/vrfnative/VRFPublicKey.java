package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

public class VRFPublicKey
{

  public static final int PUBLIC_KEY_LENGTH = 193;

  protected long publicKeyPointer;

  static {
    Library.load();
  }

  protected VRFPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  private static native int nativeGetPublicKeySize();

  private static native long nativeDeserializePublicKey(byte[] publicKeyBytes);

  public static VRFPublicKey deserialize(byte[] publicKeyBytes) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));

    long pk = nativeDeserializePublicKey(publicKeyBytes);
    return pk != 0 ? new VRFPublicKey(pk) : null;
  }

  private native byte[] nativeSerializePublicKey();

  public byte[] serializePublicKey() {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    return nativeSerializePublicKey();
  }

  private native void nativeFreePublicKey(long publicKeyPointer);

  public void freePublicKey() {
    if (publicKeyPointer != 0) {
      nativeFreePublicKey(this.publicKeyPointer);
      publicKeyPointer = 0;
    }
  }

  private native boolean nativeVerifyKey(); // jni call to Rust impl

  public boolean verifyKey() {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    return nativeVerifyKey();
  }

  private native long nativeProofToHash(VRFProof proof, FieldElement message);

  public FieldElement proofToHash(VRFProof proof, FieldElement message) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key was freed.");

    long vrfOut = nativeProofToHash(proof, message);
    return vrfOut != 0 ? new FieldElement(vrfOut) : null;
  }
}

