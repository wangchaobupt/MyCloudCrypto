package cn.edu.buaa.crypto.encryption.P2GT_plus.GCT;

import it.unisa.dia.gas.jpbc.Element;
public class Trapdoor {
    private Element K;
    private Element[] K1;
    public Trapdoor(Element k,Element[] k1){
        this.K = k;
        this.K1 = k1;
    }

    public Element getK() {
        return this.K;
    }

    public Element[] getK1() {
        return this.K1;
    }

    public int getlen(){
        int len = K.toBytes().length;
        for(int i=0;i<K1.length;i++){
            len += K1[i].toBytes().length;
        }
        return len;
    }
}
