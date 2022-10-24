package cn.edu.buaa.crypto.encryption.CPSABE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    public String[] attributes;
    public Element K0,K1;
    public Map<String, Element> Ks2,Ks3;

    public SecretKey(String[] attributes, Element k0,Element k1,Map<String, Element> ks2, Map<String, Element> ks3){
        this.attributes = attributes;
        this.K0 = k0;
        this.K1 = k1;
        this.Ks3 = ks3;
        this.Ks2 = ks2;
    }
}
