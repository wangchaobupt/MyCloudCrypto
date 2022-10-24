package cn.edu.buaa.crypto.encryption.P2GT_plus_new.DST;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_sepcialist {
    private Element TD0;
    private Element[] TD1;
    public Trapdoor_sepcialist(Element td0,Element[] td1){
        this.TD0 = td0;
        this.TD1 = td1;
    }

    public Element getTD0() {
        return TD0;
    }

    public Element[] getTD1() {
        return TD1;
    }

    public int getlen(){
        int len = TD0.toBytes().length;
        for(int i=0;i<TD1.length;i++){
            len+=TD1[i].toBytes().length;
        }
        return len;
    }
}
