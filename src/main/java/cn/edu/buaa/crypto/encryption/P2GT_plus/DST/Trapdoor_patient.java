package cn.edu.buaa.crypto.encryption.P2GT_plus.DST;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_patient {
    private Element K,K1;
    public Trapdoor_patient(Element k,Element k1){
        this.K = k;
        this.K1 = k1;
    }

    public Element getK1() {
        return K1;
    }

    public Element getK() {
        return K;
    }

    public int getlen(){
        return K.toBytes().length+K1.toBytes().length;
    }
}
