package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

public class PP_ra {
    public Element g, eggAlpha, gBeta;
    public Element[] h;

    public PP_ra(Element g, Element eggAlpha, Element gBeta, Element[] h) {
        this.g = g;
        this.eggAlpha = eggAlpha;
        this.gBeta = gBeta;
        this.h = h;
    }
}
