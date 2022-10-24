package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class TransformKey {
    public Element K0,K1;
    public Map<String, Element> Ks2,Ks3;
    public String[] A;
    public TransformKey(Element K0,Element K1,Map<String, Element> Ks2,Map<String, Element> Ks3,String[] A){
        this.K0 = K0;
        this.K1 = K1;
        this.Ks2 = Ks2;
        this.Ks3 = Ks3;
        this.A = A;
    }
}
