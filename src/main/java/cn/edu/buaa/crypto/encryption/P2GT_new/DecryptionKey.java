package cn.edu.buaa.crypto.encryption.P2GT_new;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class DecryptionKey {
    private String  accessPolicy;
    private Map<String, Element> D0;
    private Map<String, Element> D1;
    private Map<String, Element> D2;

    public DecryptionKey(String police,Map<String, Element> d0,Map<String, Element> d1,Map<String, Element> d2){
        this.accessPolicy = police;
        this.D1 = d1;
        this.D2 = d2;
        this.D0 = d0;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public Map<String, Element> getD1() {
        return D1;
    }

    public Map<String, Element> getD2() {
        return D2;
    }

    public Map<String, Element> getD0() {
        return D0;
    }

    public int getlen(){
        int len = accessPolicy.length();
        for(Map.Entry<String,Element> entry : D0.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : D1.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : D2.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
