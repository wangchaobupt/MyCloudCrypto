package cn.edu.buaa.crypto.encryption.ASFlow.RWABACE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    public Element D0,D1;
    public Map<String, Element> Ds2,Ds3;
    public String[] attributes;

    public SecretKey(Element d0, Element d1, Map<String, Element> ds2, Map<String, Element> ds3, String[] attributes) {
        D0 = d0;
        D1 = d1;
        Ds2 = ds2;
        Ds3 = ds3;
        this.attributes = attributes;
    }
}
