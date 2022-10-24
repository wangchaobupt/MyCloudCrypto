package cn.edu.buaa.crypto.encryption.LargeABS;

public class AllKey {
    public PublicKey mpk;
    public MasterSecretKey msk;
    public AllKey(PublicKey mpk, MasterSecretKey msk){
        this.mpk = mpk;
        this.msk = msk;
    }
}
