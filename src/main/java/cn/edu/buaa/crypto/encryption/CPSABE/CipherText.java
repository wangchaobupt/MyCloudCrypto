package cn.edu.buaa.crypto.encryption.CPSABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public String accessPolicy;
    public String[] attributes;
    public Element C,C0;
    public Map<String,Element> Cs1,Cs2,Cs3;

    public CipherText(String accessPolicy, String[] attributes,Element c,Element c0
            ,Map<String, Element> cs1,Map<String, Element> cs2,Map<String, Element> cs3){
        this.accessPolicy = accessPolicy;
        this.attributes = attributes;
        this.C = c;
        this.C0 = c0;
        this.Cs1 = cs1;
        this.Cs2 = cs2;
        this.Cs3 = cs3;
    }
}
