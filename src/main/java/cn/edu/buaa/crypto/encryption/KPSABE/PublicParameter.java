package cn.edu.buaa.crypto.encryption.KPSABE;

import it.unisa.dia.gas.jpbc.Element;

public class PublicParameter {
    public Element g,h,u,v,w,egh_alpha;
    public PublicParameter(Element g,Element h,Element u,Element v,Element w,Element egh_alpha){
        this.egh_alpha = egh_alpha;
        this.g = g;
        this.h = h;
        this.u = u;
        this.v = v;
        this.w = w;
    }
}
