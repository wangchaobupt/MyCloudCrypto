package cn.edu.buaa.crypto.encryption.P2GT_finall.PMT;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor_specialist {
    public Element[] TD;
    public Trapdoor_specialist(Element[] td){
        this.TD = td;
    }

    public Element[] getTD() {
        return TD;
    }

    public int getlen(){
        int len = 0;
        for(int i=0;i<this.TD.length;i++){
            len += this.TD.length;
        }
        return len;
    }
}
