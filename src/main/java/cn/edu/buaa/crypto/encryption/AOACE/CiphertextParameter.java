package cn.edu.buaa.crypto.encryption.AOACE;

public class CiphertextParameter {
    public Ciphertext c;
    public AuthenticationTag pai;
    public CiphertextParameter(Ciphertext c,AuthenticationTag pai){
        this.c = c;
        this.pai = pai;
    }
}
