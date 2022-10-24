package cn.edu.buaa.crypto.encryption.ABACEHAN;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SanCipherText {
    public Element C,C1,C2,C3;
    public Map<String, Element> Cs,Ds;
    public String accessPolicy;
    public String[] attributes;
    public SanCipherText(){}
    public SanCipherText(Element c,Element c1,Element c2,Element c3,Map<String, Element> cs,Map<String, Element> ds,String accessPolicy,String[] atts){
        C = c;
        C1 = c1;
        C2 = c2;
        C3 = c3;
        Cs = cs;
        Ds = ds;
        this.accessPolicy = accessPolicy;
        attributes = atts;
    }
}
