package cn.edu.buaa.crypto.encryption.RWkpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.HashMap;
import java.util.Map;

public class SecretKey {
    public Map<String, Element> K0,K1,K2;
    public String accessPolicy;
    public SecretKey(String accessPolicy,Map<String, Element> k0,Map<String, Element> k1,Map<String, Element> k2){
        this.accessPolicy = accessPolicy;
        this.K0 = k0;
        this.K1 = k1;
        this.K2 = k2;
    }
}
