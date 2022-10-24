package cn.edu.buaa.crypto.encryption.P2GT_new;

import it.unisa.dia.gas.jpbc.Element;

public class PublicKey {
    public Element g,h,u,w,ega;
    public PublicKey(Element g,Element h,Element u,Element w,Element ega){
        this.ega = ega;
        this.g = g;
        this.h = h;
        this.u = u;
        this.w = w;
    }
}
