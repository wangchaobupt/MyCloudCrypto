package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class sk_KGCSPParameter {
    private Map<String, Element> d1;
    private Map<String, Element> d2;
    public sk_KGCSPParameter(Map<String, Element> d1, Map<String, Element> d2){
        this.d1 = d1;
        this.d2 = d2;
    }

    public Map<String, Element> getD1() {
        return d1;
    }

    public Map<String, Element> getD2() {
        return d2;
    }

    public int getlen(){
        int len = 0;
        for(Map.Entry<String,Element> entry : d1.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : d2.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
