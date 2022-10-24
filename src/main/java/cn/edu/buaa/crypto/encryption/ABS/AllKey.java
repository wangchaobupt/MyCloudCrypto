package cn.edu.buaa.crypto.encryption.ABS;

public class AllKey {
    public MasterSecretKey msk;
    public PublicKey mpk;
    public AllKey(PublicKey mpk,MasterSecretKey msk){
        this.mpk = mpk;
        this.msk = msk;
    }
}
