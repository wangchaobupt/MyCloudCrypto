package cn.edu.buaa.crypto.encryption.AGHO_SPS;

public class AllKey {
    public SigningKey sk;
    public VerificationKey vk;
    public AllKey(SigningKey sk,VerificationKey vk){
        this.sk = sk;
        this.vk = vk;
    }
}
