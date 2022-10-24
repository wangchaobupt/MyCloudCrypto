package cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS;

public class AllKey {
    public SecretKey esk;
    public PublicKey evk;

    public AllKey(SecretKey esk, PublicKey evk) {
        this.esk = esk;
        this.evk = evk;
    }
}
