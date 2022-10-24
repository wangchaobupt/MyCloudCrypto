package cn.edu.buaa.crypto.encryption.KPSABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public String[] attributes;
    public Element C,C0;
    public Map<String, Element> Cs1,Cs2;
    public CipherText(Element C, Element C0,Map<String, Element> Cs1,Map<String, Element> Cs2,String[] attributes){
        this.attributes = attributes;
        this.C = C;
        this.C0 = C0;
        this.Cs1 = Cs1;
        this.Cs2 = Cs2;
    }
    public CipherText(){}

    public int getlen(){
        int len = C.toBytes().length + C0.toBytes().length;
        for(String att : Cs1.keySet()){
            len += Cs1.get(att).toBytes().length + Cs2.get(att).toBytes().length;
        }
        return len;
    }
}
