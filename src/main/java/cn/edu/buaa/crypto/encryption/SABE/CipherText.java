package cn.edu.buaa.crypto.encryption.SABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public Element C0,C1,C2,D0;
    public Map<String, Element> Ds1,Ds2;
    public String accessPolicy;
    public String[] attributes;
    public CipherText(Element C0,Element C1,Element C2,Element D0,Map<String, Element> Ds1,Map<String, Element> Ds2,String accessPolicy,String[] attributes){
        this.C0 = C0;
        this.C1 = C1;
        this.C2 = C2;
        this.Ds1 = Ds1;
        this.Ds2 = Ds2;
        this.D0 = D0;
        this.accessPolicy = accessPolicy;
        this.attributes = attributes;
    }

    public int getlen(){
        int len = C0.toBytes().length + C1.toBytes().length + C2.toBytes().length + D0.toBytes().length;
        for(String att : Ds1.keySet()){
            len += Ds1.get(att).toBytes().length + Ds2.get(att).toBytes().length;
        }
        return len;
    }
}
