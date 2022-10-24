package cn.edu.buaa.crypto.encryption.DSFlow;

import cn.edu.buaa.crypto.encryption.AGHO_SPS.Signature;
import it.unisa.dia.gas.jpbc.Element;

public class EncryptionKey {
    public String[] A;
    public Element[] M;
    public Signature sign;
    public EncryptionKey(String[] A,Element[] M,Signature sign){
        this.A = A;
        this.M = M;
        this.sign = sign;
    }
}
