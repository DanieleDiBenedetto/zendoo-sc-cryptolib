package com.horizen.poseidonnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;

import java.util.Arrays;

public class PoseidonHash {

    public static final int HASH_LENGTH = 96;

    static {
        Library.load();
    }

    private static native long nativeComputeHash(FieldElement[] fieldElement); // jni call to Rust impl

    public static FieldElement computeHash(FieldElement[] fieldElement) {
        long hash = nativeComputeHash(fieldElement);
        return hash != 0 ? new FieldElement(hash) : null;
    }
}
