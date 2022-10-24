package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    private Element C0,C1,C2;
    private Map<String,Element> C;
    private String[] attributes;
    private String w0;
    public CipherText(Element c0, Element c1, Map<String,Element> c, Element c2,String[] w,String w0){
        this.C = c;
        this.C0 = c0;
        this.C1 = c1;
        this.C2 = c2;
        this.attributes = w;
        this.w0 = w0;
    }

    public Element getC0() {
        return C0;
    }

    public Element getC1() {
        return C1;
    }

    public Element getC2() {
        return C2;
    }

    public Map<String,Element> getC() {
        return C;
    }

    public String[] getAttributes() {
        return attributes;
    }

    public String getW0() {
        return w0;
    }

    public int getlen(){
        int len = C0.toBytes().length + C1.toBytes().length + C2.toBytes().length + w0.length();
        for(int i=0;i<attributes.length;i++) len += attributes[i].length();
        for(Map.Entry<String,Element> entry : C.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        return len;
    }
}
