package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFProof
{

  public static int PROOF_LENGTH = 385;

  private long proofPointer;

  static {
    Library.load();
  }

  protected VRFProof(long proofPointer) {
    if (proofPointer == 0)
      throw new IllegalArgumentException("Proof pointer must be not null.");
    this.proofPointer = proofPointer;
  }

  private static native byte[] nativeSerializeProof(long proofPointer);

  private static native long nativeDeserializeProof(byte[] proofBytes);

  private static native void nativefreeProof(long proofPointer);

  public static VRFProof deserialize(byte[] proofBytes) {
    if (proofBytes.length != PROOF_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect proof length, %d expected, %d found", PROOF_LENGTH, proofBytes.length));

    long vrfProof = nativeDeserializeProof(proofBytes);
    return vrfProof != 0 ? new VRFProof(vrfProof) : null;
  }

  public byte[] serializeProof() {
    return nativeSerializeProof(this.proofPointer);
  }

  public void freeProof() {
    if (proofPointer != 0) {
      nativefreeProof(this.proofPointer);
      proofPointer = 0;
    }
  }
}

