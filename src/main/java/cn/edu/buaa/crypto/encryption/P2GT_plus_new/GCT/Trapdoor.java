package cn.edu.buaa.crypto.encryption.P2GT_plus_new.GCT;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor {
    private Element TD;
    private Element[] TDk;
    public Trapdoor(Element td,Element[] tdk){
        this.TD = td;
        this.TDk = tdk;
    }

    public Element getTD() {
        return TD;
    }

    public Element[] getTDk() {
        return TDk;
    }

    public int getlen(){
        int len = TD.toBytes().length;
        for(int i=0;i<TDk.length;i++){
            len += TDk[i].toBytes().length;
        }
        return len;
    }
}
