package cn.edu.buaa.crypto.encryption.ABACEHAN;

public class AllSecretKey {
    public MasterSecretKey msk;
    public SanSercetKey ssk;
    public AllSecretKey(MasterSecretKey msk,SanSercetKey ssk){
        this.msk = msk;
        this.ssk = ssk;
    }
}
