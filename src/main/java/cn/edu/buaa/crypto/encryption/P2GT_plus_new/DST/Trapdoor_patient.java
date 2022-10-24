package cn.edu.buaa.crypto.encryption.P2GT_plus_new.DST;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_patient {
    private Element TD0,TD1;
    public Trapdoor_patient(Element td0,Element td1){
        this.TD0 = td0;
        this.TD1 = td1;
    }

    public Element getTD0() {
        return TD0;
    }

    public Element getTD1() {
        return TD1;
    }

    public int getlen(){
        return TD0.toBytes().length+TD1.toBytes().length;
    }
}
