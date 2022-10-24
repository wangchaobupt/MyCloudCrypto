package cn.edu.buaa.crypto.encryption.ABACEHAN;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    private Element K,L,R;
    private Map<String, Element> K_x;
    private String[] attributes;
    private String ID;
    public SecretKey(Element k,Element l,Element r,Map<String, Element> k_x,String[] A,String id){
        K = k;
        L = l;
        R = r;
        K_x = k_x;
        attributes = A;
        ID = id;
    }

    public Element getK() {
        return K;
    }

    public Element getR() {
        return R;
    }

    public Element getL() {
        return L;
    }

    public Map<String, Element> getK_x() {
        return K_x;
    }

    public String[] getAttributes() {
        return attributes;
    }

    public String getID() {
        return ID;
    }
}
