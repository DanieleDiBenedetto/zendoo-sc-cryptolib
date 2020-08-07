package com.horizen.librustsidechains;

import java.nio.ByteBuffer;

public class FieldElement {

    public static int FIELD_ELEMENT_LENGTH = 96;

    public long fieldElementPointer;

    static {
        Library.load();
    }

    public FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native long nativeCreateFromLong(long value);

    public static FieldElement createFromLong(long value) {
        return new FieldElement(nativeCreateFromLong(value));
    }

    private static native long nativeCreateRandom();

    public static FieldElement createRandom() { return new FieldElement(nativeCreateRandom()); }

    private static native int nativeGetFieldElementSize();

    public static int getFieldElementSize() {return  nativeGetFieldElementSize();}

    private native byte[] nativeSerializeFieldElement();

    public byte[] serializeFieldElement() {
        if (fieldElementPointer == 0)
            throw new IllegalArgumentException("Field element was freed.");

        return nativeSerializeFieldElement();
    }

    private static native long nativeDeserializeFieldElement(byte[] fieldElementBytes);

    public static FieldElement deserialize(byte[] fieldElementBytes) {
        if (fieldElementBytes.length != FIELD_ELEMENT_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect field element length, %d expected, %d found",
                    FIELD_ELEMENT_LENGTH, fieldElementBytes.length));

        long fe = nativeDeserializeFieldElement(fieldElementBytes);
        return fe != 0 ? new FieldElement(fe) : null;
    }

    private static native void nativeFreeFieldElement(long fieldElementPointer);

    public void freeFieldElement() {
        if (fieldElementPointer != 0) {
            nativeFreeFieldElement(this.fieldElementPointer);
            fieldElementPointer = 0;
        }
    }

    private native boolean nativeEquals(FieldElement fe);

    @Override
    public boolean equals(Object o) {

        if (o == this) {
            return true;
        }

        if (!(o instanceof FieldElement)) {
            return false;
        }

        return nativeEquals((FieldElement) o);
    }
}
