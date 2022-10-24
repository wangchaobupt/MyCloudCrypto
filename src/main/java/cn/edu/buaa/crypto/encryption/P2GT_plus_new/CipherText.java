package cn.edu.buaa.crypto.encryption.P2GT_plus_new;

import it.unisa.dia.gas.jpbc.Element;

public class CipherText {
    private cn.edu.buaa.crypto.encryption.P2GT_new.CipherText CT;
    private Element[] T,T1;
    public CipherText(cn.edu.buaa.crypto.encryption.P2GT_new.CipherText ct, Element[] t, Element[] t1){
        this.CT = ct;
        this.T = t;
        this.T1 = t1;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_new.CipherText getCT() {
        return CT;
    }

    public Element[] getT() {
        return T;
    }

    public Element[] getT1() {
        return T1;
    }

    public int getlen(){
        int len = CT.getlen();
        for(int i=0;i<T.length;i++){
            len+=T[i].toBytes().length;
        }
        for(int i=0;i<T1.length;i++){
            len+=T1[i].toBytes().length;
        }
        return len;
    }

}
