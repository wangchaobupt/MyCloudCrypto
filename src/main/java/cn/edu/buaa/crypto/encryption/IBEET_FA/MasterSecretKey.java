package cn.edu.buaa.crypto.encryption.IBEET_FA;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private Element s1,s2;
    public MasterSecretKey(Element s1,Element s2){
        this.s1 = s1;
        this.s2 = s2;
    }

    public Element getS1() {
        return s1;
    }

    public Element getS2() {
        return s2;
    }
}
