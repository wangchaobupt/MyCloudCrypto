package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Proof {
    public Element c, y1, y2, n;
    public Element A;
    public Map<String, Element> Xs, Ys, Zs, Fs, Gs, Is, y3s, y4s, ls, ps;

    public Proof(Map<String, Element> xs, Map<String, Element> ys, Map<String, Element> zs, Map<String, Element> fs, Map<String, Element> gs, Map<String, Element> is, Element A, Element c, Element y1, Element y2, Map<String, Element> y3s, Map<String, Element> y4s, Element n, Map<String, Element> ls, Map<String, Element> ps) {
        this.c = c;
        this.y1 = y1;
        this.y2 = y2;
        this.n = n;
        Xs = xs;
        Ys = ys;
        Zs = zs;
        Fs = fs;
        Gs = gs;
        Is = is;
        this.A = A;
        this.y3s = y3s;
        this.y4s = y4s;
        this.ls = ls;
        this.ps = ps;
    }
}
