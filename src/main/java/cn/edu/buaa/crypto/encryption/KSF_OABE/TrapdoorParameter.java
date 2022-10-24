package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class TrapdoorParameter {
    private Element Tq,D1;
    private Map<String, Element> I1;
    private Map<String, Element> I2;
    private String accessPolicy;

    public TrapdoorParameter(Element t,Map<String, Element> i1,Map<String, Element> i2,Element d1,String accessPolicy){
        this.D1 = d1;
        this.I1 = i1;
        this.I2 = i2;
        this.Tq = t;
        this.accessPolicy = accessPolicy;
    }

    public Element getD1() {
        return D1;
    }

    public Element getTq() {
        return Tq;
    }

    public Map<String, Element> getI1() {
        return I1;
    }

    public Map<String, Element> getI2() {
        return I2;
    }

    public String getAccessPolicy() {
        return accessPolicy;
    }

    public int getlen(){
        int len = Tq.toBytes().length + D1.toBytes().length + accessPolicy.length();
        for(Map.Entry<String,Element> entry : I1.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : I2.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
