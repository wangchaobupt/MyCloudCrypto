package cn.edu.buaa.crypto.encryption.P2GT_new.PMT;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_doctor {
    private Element TD;
    public Trapdoor_doctor(Element td){
        this.TD = td;
    }

    public Element getTD() {
        return TD;
    }

    public int getlen(){
        return this.TD.toBytes().length;
    }
}
