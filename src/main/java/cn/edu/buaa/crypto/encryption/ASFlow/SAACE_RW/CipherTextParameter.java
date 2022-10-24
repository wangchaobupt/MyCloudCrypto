package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;

public class CipherTextParameter {
    public Proof proof;
    public CipherText CT;

    public CipherTextParameter(Proof proof, CipherText CT) {
        this.proof = proof;
        this.CT = CT;
    }
}
