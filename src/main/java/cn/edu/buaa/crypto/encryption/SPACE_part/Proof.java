package cn.edu.buaa.crypto.encryption.SPACE_part;

import it.unisa.dia.gas.jpbc.Element;

public class Proof {
    public Element X,Y,Z,W,c,y1,y2,n,t,r;
    public Proof(Element x,Element y,Element z,Element w
            ,Element c,Element y1,Element y2,Element n,Element t,Element r){
        X = x;
        Y = y;
        Z = z;
        W = w;
        this.c = c;
        this.y1 = y1;
        this.y2 = y2;
        this.n = n;
        this.t = t;
        this.r = r;
    }
}
