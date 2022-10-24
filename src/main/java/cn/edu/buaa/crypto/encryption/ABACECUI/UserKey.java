package cn.edu.buaa.crypto.encryption.ABACECUI;

public class UserKey {
    public PublicKey pk;
    public SecretKey sk;
    public UserKey(PublicKey pk,SecretKey sk){
        this.pk = pk;
        this.sk = sk;
    }
}
