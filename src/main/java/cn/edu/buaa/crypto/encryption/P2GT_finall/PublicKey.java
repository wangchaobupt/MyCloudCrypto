package cn.edu.buaa.crypto.encryption.P2GT_finall;

import it.unisa.dia.gas.jpbc.Element;

public class PublicKey {
    public Element g,h,ehu,u;
    public int maxnum;
    public PublicKey(Element g, Element h, Element ehu, Element u,int num){
        this.ehu = ehu;
        this.g = g;
        this.h = h;
        this.u = u;
        this.maxnum = num;
    }
}
