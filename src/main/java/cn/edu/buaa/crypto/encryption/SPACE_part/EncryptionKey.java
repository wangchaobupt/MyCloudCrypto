package cn.edu.buaa.crypto.encryption.SPACE_part;

import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;

public class EncryptionKey {
    public String[] attributes;
    public String accessPolicy;
    public Element[] M;
    public SignParameter sign_A;

    public EncryptionKey(String[] A, String accessPolicy,Element[] M,SignParameter sign_A){
        attributes = A;
        this.M = M;
        this.accessPolicy = accessPolicy;
        this.sign_A = sign_A;
    }
}
