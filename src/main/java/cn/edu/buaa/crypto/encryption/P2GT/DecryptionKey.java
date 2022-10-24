package cn.edu.buaa.crypto.encryption.P2GT;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class DecryptionKey {
    private Element D;
    private  Map<String, Element> D1;
    private Map<String, Element> D2;
    private String[] attributes;
    public DecryptionKey(Element d,Map<String, Element> d1,Map<String, Element> d2,String[] as){
        this.D = d;
        this.D1 = d1;
        this.D2 = d2;
        this.attributes = as;
    }

    public Element getD() {
        return D;
    }

    public Map<String, Element> getD1() {
        return D1;
    }

    public Map<String, Element> getD2() {
        return D2;
    }

    public String[] getAttributes() {
        return attributes;
    }
}

