package cn.edu.buaa.crypto.encryption.P2GT;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    private String  accessPolicy;
    private  Element c0,c;
    private Map<String, Element> C1s;
    private Map<String, Element> C2s;

    public CipherText(String police,Element c0,Element c,Map<String, Element> c1,Map<String, Element> c2){
        this.accessPolicy = police;
        this.c = c;
        this.c0 = c0;
        this.C1s = c1;
        this.C2s = c2;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public Element getC() {
        return c;
    }

    public Element getC0() {
        return c0;
    }

    public Map<String, Element> getC1s() {
        return C1s;
    }

    public Map<String, Element> getC2s() {
        return C2s;
    }
}
