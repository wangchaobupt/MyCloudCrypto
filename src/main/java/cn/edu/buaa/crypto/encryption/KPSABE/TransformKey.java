package cn.edu.buaa.crypto.encryption.KPSABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class TransformKey {
    public Map<String, Element> Ds0,Ds1,Ds2;
    public String accessPolicy;
    public TransformKey(Map<String, Element> Ds0,Map<String, Element> Ds1,Map<String, Element> Ds2,String accessPolicy){
        this.Ds0 = Ds0;
        this.Ds1 = Ds1;
        this.Ds2 = Ds2;
        this.accessPolicy = accessPolicy;
    }
}
