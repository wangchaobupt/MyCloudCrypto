package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherData {
    public String accessPolicy;
    public Element C, CPrime;
    public Map<String, Element> Cs;
    public Map<String, Element> Ds;

    public CipherData(String accessPolicy, Element c, Element CPrime, Map<String, Element> cs, Map<String, Element> ds) {
        this.accessPolicy = accessPolicy;
        C = c;
        this.CPrime = CPrime;
        Cs = cs;
        Ds = ds;
    }
}
