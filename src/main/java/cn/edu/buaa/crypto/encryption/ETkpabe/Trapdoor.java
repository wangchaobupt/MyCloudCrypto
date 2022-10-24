package cn.edu.buaa.crypto.encryption.ETkpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Trapdoor {
    private Map<String, Element> Td;
    private String accessPolicy;

    public Trapdoor(Map<String, Element> td,String t){
        this.Td = td;
        this.accessPolicy = t;
    }

    public Map<String, Element> getTd() {
        return Td;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public int getlen(){
        int len = accessPolicy.length();
        for(Map.Entry<String,Element> entry : Td.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
