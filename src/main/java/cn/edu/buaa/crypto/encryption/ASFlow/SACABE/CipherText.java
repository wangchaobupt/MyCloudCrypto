package cn.edu.buaa.crypto.encryption.ASFlow.SACABE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Map;

public class CipherText {
    public String accessPolicy;
    public ArrayList<Element> ct0;
    public Map<String, ArrayList<Element>> ct;
    public Element C;

    public CipherText(String accessPolicy, ArrayList<Element> ct0, Map<String, ArrayList<Element>> ct, Element C) {
        this.accessPolicy = accessPolicy;
        this.ct0 = ct0;
        this.ct = ct;
        this.C = C;
    }
}
