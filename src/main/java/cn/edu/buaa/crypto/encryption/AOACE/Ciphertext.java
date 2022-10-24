package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Ciphertext {
    public String accessPolicy;
    public String[] attributes;
    public Element C,C0;
    public Map<String, Element> Cs1,Cs2,Cs3,Cs4,Cs5;
    public Ciphertext(Element C,Element C0,Map<String, Element> Cs1,Map<String, Element> Cs2,Map<String, Element> Cs3,Map<String, Element> Cs4,Map<String, Element> Cs5,String accessPolicy,String[] attributes){
        this.accessPolicy = accessPolicy;
        this.C = C;
        this.C0 = C0;
        this.Cs1 = Cs1;
        this.Cs2 = Cs2;
        this.Cs3 = Cs3;
        this.Cs4 = Cs4;
        this.Cs5 = Cs5;
        this.attributes = attributes;
    }
}
