package cn.edu.buaa.crypto.encryption.ETkpabe;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public Element C1,C3,C6;
    public byte[] C2;
    public Map<String,Element> C4,C5;
    public String[] S,S1;
    public CipherText(String[] s,String[] s1,Element c1,byte[] c2,Element c3,Map<String,Element> c4,Map<String,Element> c5,Element c6){
        this.C1 = c1;
        this.C2 = c2;
        this.C3 = c3;
        this.C4 = c4;
        this.C5 = c5;
        this.C6 = c6;
        this.S = s;
        this.S1 = s1;
    }

    public int getlen(){
        int len = C1.toBytes().length + C3.toBytes().length + C6.toBytes().length + C2.length;
        for(int i=0;i<S.length;i++) len += S[i].length();
        for(int i=0;i<S1.length;i++) len += S1[i].length();
        for(Map.Entry<String,Element> entry : C4.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : C5.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
