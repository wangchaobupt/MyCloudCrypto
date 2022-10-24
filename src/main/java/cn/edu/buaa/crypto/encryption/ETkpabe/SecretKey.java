package cn.edu.buaa.crypto.encryption.ETkpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    private Map<String, Element> D;
    private Map<String, Element> T;
    private String  accessPolicy;
    private String  accessPolicy1;
    public SecretKey(Map<String, Element> d,Map<String, Element> t,String policy,String policy1){
        this.D = d;
        this.T = t;
        this.accessPolicy = policy;
        this.accessPolicy1 = policy1;
    }

    public Map<String, Element> getD() {
        return D;
    }

    public Map<String, Element> getT() {
        return T;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public String getAccessPolicy1() {
        return accessPolicy1;
    }

    public int getlen(){
        int len = accessPolicy.length() + accessPolicy1.length();
        for(Map.Entry<String,Element> entry : D.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : T.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
