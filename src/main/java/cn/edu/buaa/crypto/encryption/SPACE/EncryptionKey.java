package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.encryption.ABS.SecretKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;

import it.unisa.dia.gas.jpbc.Element;

public class EncryptionKey {
    public String accessPolicy_T;
    public String[] attributes;
    public Element[] M;
    public SecretKey sk;
    public SignParameter sign_A;

    public EncryptionKey(String T,String[] A,Element[] M,SecretKey sk,SignParameter sign_A){
        accessPolicy_T = T;
        attributes = A;
        this.M = M;
        this.sk = sk;
        this.sign_A = sign_A;
    }
}
