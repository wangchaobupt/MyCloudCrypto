package cn.edu.buaa.crypto.encryption.SABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    public Element gg_alpha,gg_beta,gt,gt1;
    public Map<String, Element> ht,ht1;
    public String[] attributes;
    public SecretKey(Element gg_alpha,Element gg_beta,Element gt,Element gt1,Map<String, Element> ht,Map<String, Element> ht1,String[] attributes){
        this.gg_alpha = gg_alpha;
        this.gg_beta = gg_beta;
        this.gt = gt;
        this.gt1 = gt1;
        this.ht = ht;
        this.ht1 = ht1;
        this.attributes = attributes;
    }
}
