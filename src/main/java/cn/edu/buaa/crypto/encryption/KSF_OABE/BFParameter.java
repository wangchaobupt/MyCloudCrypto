package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

public class BFParameter {
    private Element q;
    public BFParameter(Element q){
        this.q = q;
    }

    public Element getQ() {
        return q;
    }

    public int getlen(){
        return q.toBytes().length;
    }
}
