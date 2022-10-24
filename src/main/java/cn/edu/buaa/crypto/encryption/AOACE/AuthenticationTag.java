package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;

public class AuthenticationTag {
    public AuthenticationCiphertext c1;
    public Element c2;
    public AuthenticationTag(AuthenticationCiphertext c1,Element c2){
        this.c1 = c1;
        this.c2 = c2;
    }
}
