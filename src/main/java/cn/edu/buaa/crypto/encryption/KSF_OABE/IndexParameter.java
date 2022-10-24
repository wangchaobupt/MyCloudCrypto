package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.EventListener;

public class IndexParameter {
    private Element K1,K2;
    private Element[] K;
    private int len;
    public IndexParameter(Element k1, Element k2,Element[] k,int n){
        this.K = k;
        this.K1 = k1;
        this.K2 = k2;
        this.len = n;
    }

    public Element getK1() {
        return K1;
    }

    public Element getK2() {
        return K2;
    }

    public Element[] getK() {
        return K;
    }

    public int getLen() {
        return len;
    }

    public int getlen(){
        int len = K1.toBytes().length + K2.toBytes().length;
        for(int i=0;i<K.length;i++) len+=K[i].toBytes().length;
        return len;
    }
}
