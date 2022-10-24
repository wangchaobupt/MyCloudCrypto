package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

public class QueryPrivateKey {
    private Element QK;
    public QueryPrivateKey(Element k){
        this.QK = k;
    }

    public Element getQK() {
        return QK;
    }

    public int getlen(){
        return QK.toBytes().length;
    }
}
