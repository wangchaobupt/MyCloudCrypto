package cn.edu.buaa.crypto.encryption.P2GT_plus;

import it.unisa.dia.gas.jpbc.Element;

public class DecryptionKey {
    private cn.edu.buaa.crypto.encryption.P2GT_finall.DecryptionKey sk;
    private Element K,K1;
    public DecryptionKey(cn.edu.buaa.crypto.encryption.P2GT_finall.DecryptionKey sk, Element k, Element k1){
        this.sk = sk;
        this.K = k;
        this.K1 = k1;
    }

    public Element getK() {
        return K;
    }

    public Element getK1() {
        return K1;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_finall.DecryptionKey getSk() {
        return sk;
    }
}

