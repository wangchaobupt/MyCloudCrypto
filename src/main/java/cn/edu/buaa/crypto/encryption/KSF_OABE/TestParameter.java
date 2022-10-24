package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

public class TestParameter {
    private boolean tag;
    private CipherText CT;
    private IndexParameter IX;
    private Element Q;
    public TestParameter(boolean tag){
        this.tag = tag;
    }

    public TestParameter(boolean tag,CipherText c,IndexParameter ix,Element q){
        this.tag = tag;
        this.CT = c;
        this.IX = ix;
        this.Q = q;
    }
//    public void getTulp(CipherText c,IndexParameter ix,Element q){
//        this.CT = c;
//        this.IX = ix;
//        this.Q = q;
//    }
    public boolean getTag(){
        return tag;
    }

    public CipherText getCT() {
        return CT;
    }

    public Element getQ() {
        return Q;
    }

    public IndexParameter getIX() {
        return IX;
    }

    public int getlen(){
        return Q.toBytes().length + CT.getlen() + IX.getlen();
    }
}
