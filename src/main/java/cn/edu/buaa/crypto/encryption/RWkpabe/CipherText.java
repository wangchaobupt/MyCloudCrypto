package cn.edu.buaa.crypto.encryption.RWkpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    private String[] attributes;
    private Element C,C0;
    private Map<String, Element> C1,C2;
    public CipherText(String[] attributes,Element c,Element c0,Map<String, Element> c1,Map<String, Element> c2){
        this.attributes = attributes;
        this.C = c;
        this.C0 = c0;
        this.C1 = c1;
        this.C2 = c2;
    }

    public Element getC0() {
        return C0;
    }

    public Element getC() {
        return C;
    }

    public String[] getAttributes() {
        return attributes;
    }

    public Map<String, Element> getC1() {
        return C1;
    }

    public Map<String, Element> getC2() {
        return C2;
    }
}
