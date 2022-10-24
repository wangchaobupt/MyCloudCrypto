package cn.edu.buaa.crypto.encryption.CPSABE;

import it.unisa.dia.gas.jpbc.Element;
public class PublicKey {
    public Element g,h,u,v,w,egg_alpha;
    public PublicKey(Element g, Element h, Element u,Element v,Element w,Element egg_alpha){
        this.g = g;
        this.h = h;
        this.u = u;
        this.v = v;
        this.w = w;
        this.egg_alpha = egg_alpha;
    }

}
