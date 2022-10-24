package cn.edu.buaa.crypto.encryption.DSFlow;

import it.unisa.dia.gas.jpbc.Element;

public class Proof {
    public Element X,Y,F,A,B,c,y1,y2,n,t,r,o;
    public Proof(Element X,Element Y,Element F,Element A,Element B,Element c,Element y1,Element y2,Element n,Element t,Element r,Element o){
        this.X = X;
        this.Y = Y;
        this.F = F;
        this.A = A;
        this.B = B;
        this.c = c;
        this.y1 = y1;
        this.y2 = y2;
        this.n = n;
        this.t = t;
        this.r = r;
        this.o = o;
    }

    public int getlen(){
        return X.toBytes().length + Y.toBytes().length + F.toBytes().length + A.toBytes().length
        + B.toBytes().length + c.toBytes().length + y1.toBytes().length + y2.toBytes().length
        + n.toBytes().length + t.toBytes().length + r.toBytes().length + o.toBytes().length;
    }
}
