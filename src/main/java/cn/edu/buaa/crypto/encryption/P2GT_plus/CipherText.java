package cn.edu.buaa.crypto.encryption.P2GT_plus;

import it.unisa.dia.gas.jpbc.Element;

public class CipherText {
    private cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText CT;
    private Element[] T,T1,T2;
    public CipherText(cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText ct, Element[] t, Element[] t1, Element[] t2){
        this.CT = ct;
        this.T = t;
        this.T1 = t1;
        this.T2 = t2;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText getCT() {
        return CT;
    }

    public Element[] getT() {
        return T;
    }

    public Element[] getT1() {
        return T1;
    }

    public Element[] getT2() {
        return T2;
    }
}
