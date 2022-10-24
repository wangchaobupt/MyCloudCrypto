package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

public class sk_TAParameter {
    private Element d0,d1;
    public sk_TAParameter(Element d0,Element d1){
        this.d0 = d0;
        this.d1 = d1;
    }

    public Element getD0() {
        return d0;
    }

    public Element getD1() {
        return d1;
    }

    public int getlen(){
        return d0.toBytes().length + d1.toBytes().length;
    }
}
