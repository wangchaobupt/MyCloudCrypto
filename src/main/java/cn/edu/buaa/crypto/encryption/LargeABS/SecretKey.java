package cn.edu.buaa.crypto.encryption.LargeABS;

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;

public class SecretKey {
    public String accessPolicy;
    public Map<String, Element> D,D1;
    public Map<String, Map<String, Element>> D2;
    public SecretKey(String accessPolicy, Map<String, Element> D, Map<String, Element> D1,Map<String, Map<String, Element>> D2){
        this.accessPolicy = accessPolicy;
        this.D = D;
        this.D1 = D1;
        this.D2 = D2;
    }
}
