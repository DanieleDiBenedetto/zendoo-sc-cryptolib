package com.horizen.sigproofnative;

public class CreateProofResult {
    private byte[] proof;
    private long quality;

    protected CreateProofResult(byte[] proof, long quality) {
        this.proof = proof;
        this.quality = quality;
    }

    public byte[] getProof() {
        return this.proof;
    }

    public long getQuality() {
        return this.quality;
    }
}