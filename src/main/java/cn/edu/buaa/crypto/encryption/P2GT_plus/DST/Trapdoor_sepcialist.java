package cn.edu.buaa.crypto.encryption.P2GT_plus.DST;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_sepcialist {
    private Element K;
    private Element[] K1;
    public Trapdoor_sepcialist(Element k,Element[] k1){
        this.K = k;
        this.K1 = k1;
    }

    public Element getK() {
        return K;
    }

    public Element[] getK1() {
        return K1;
    }

    public int getlen(){
        int len = K.toBytes().length;
        for(int i=0;i<K1.length;i++){
            len+=K1[i].toBytes().length;
        }
        return len;
    }
}
