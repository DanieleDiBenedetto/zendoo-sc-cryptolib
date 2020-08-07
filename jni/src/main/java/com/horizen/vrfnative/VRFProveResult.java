package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.librustsidechains.Library;


public class VRFProveResult {
    protected long vrfProof;
    protected long vrfOutput;

    static {
        Library.load();
    }

    protected VRFProveResult(long vrfProof, long vrfOutput) {
        this.vrfProof = vrfProof;
        this.vrfOutput = vrfOutput;
    }

    public VRFProof getVRFProof() {
        return new VRFProof(this.vrfProof);
    }

    public FieldElement getVRFOutput() {
        return new FieldElement(this.vrfOutput);
    }
}