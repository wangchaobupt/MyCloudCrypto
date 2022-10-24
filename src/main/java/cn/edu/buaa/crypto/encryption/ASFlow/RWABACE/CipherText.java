package cn.edu.buaa.crypto.encryption.ASFlow.RWABACE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public String accessPolicy;
    public Element C,C0;
    public Map<String, Element> Cs1,Cs2,Cs3;

    public CipherText(String accessPolicy, Element c, Element c0, Map<String, Element> cs1, Map<String, Element> cs2, Map<String, Element> cs3) {
        this.accessPolicy = accessPolicy;
        C = c;
        C0 = c0;
        Cs1 = cs1;
        Cs2 = cs2;
        Cs3 = cs3;
    }
}
