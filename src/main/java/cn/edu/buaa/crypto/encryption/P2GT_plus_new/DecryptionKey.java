package cn.edu.buaa.crypto.encryption.P2GT_plus_new;

import it.unisa.dia.gas.jpbc.Element;

public class DecryptionKey {
    private cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey SK;
    private Element K,K1;
    public DecryptionKey(cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey sk, Element k, Element k1){
        this.SK = sk;
        this.K = k;
        this.K1 = k1;
    }

    public Element getK1() {
        return K1;
    }

    public Element getK() {
        return K;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey getSK() {
        return SK;
    }

    public int getlen(){
        int len = SK.getlen();
        return len + K.toBytes().length + K1.toBytes().length;
    }
}
