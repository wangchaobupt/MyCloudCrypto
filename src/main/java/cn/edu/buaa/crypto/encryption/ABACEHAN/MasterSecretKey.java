package cn.edu.buaa.crypto.encryption.ABACEHAN;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private Element a,alpha,gamma;
    public MasterSecretKey(Element a,Element alpha,Element gamma){
        this.a = a;
        this.alpha = alpha;
        this.gamma = gamma;
    }

    public Element getA() {
        return a;
    }

    public Element getAlpha() {
        return alpha;
    }

    public Element getGamma() {
        return gamma;
    }
}

