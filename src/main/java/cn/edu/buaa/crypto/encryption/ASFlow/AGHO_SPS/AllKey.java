package cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS;

public class AllKey {
    public VerficationKey svk;
    public SigningKey ssk;

    public AllKey(VerficationKey svk, SigningKey ssk) {
        this.svk = svk;
        this.ssk = ssk;
    }
}
