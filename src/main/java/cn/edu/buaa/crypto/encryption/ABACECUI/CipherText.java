package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Map;

public class CipherText {
    public String accessPolicy;
    public ArrayList<Element> ct0;
    public Map<String, ArrayList<Element>> ct;
    public Element ct1;
    public CipherText(){}
    public CipherText(ArrayList<Element> ct0,Map<String, ArrayList<Element>> ct,Element ct1,String accessPolicy){
        this.ct0 = ct0;
        this.ct = ct;
        this.ct1 = ct1;
        this.accessPolicy = accessPolicy;
    }
}
