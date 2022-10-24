package cn.edu.buaa.crypto.encryption.P2GT_finall;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class DecryptionKey {
    Map<String, Element> D1;
    Map<String, Element> D2;
    private String  accessPolicy;
    public DecryptionKey(String police,Map<String, Element> d1,Map<String, Element> d2){
        this.accessPolicy = police;
        this.D1 = d1;
        this.D2 = d2;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public Map<String, Element> getD1() {
        return D1;
    }

    public Map<String, Element> getD2() {
        return D2;
    }
}
