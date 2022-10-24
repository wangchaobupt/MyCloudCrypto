package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import it.unisa.dia.gas.jpbc.Element;
public class Proof {
    public Element X,Y,Z,T,F,G,H,I,J,c,y1,y2,n,t,r,p,o,q;

    public Proof(Element x, Element y, Element z, Element t, Element f, Element g, Element h, Element i, Element j, Element c, Element y1, Element y2, Element n, Element t1, Element r, Element p,Element o,Element q) {
        X = x;
        Y = y;
        Z = z;
        T = t;
        F = f;
        G = g;
        H = h;
        I = i;
        J = j;
        this.c = c;
        this.y1 = y1;
        this.y2 = y2;
        this.n = n;
        this.t = t1;
        this.r = r;
        this.p = p;
        this.o = o;
        this.q = q;
    }
}
