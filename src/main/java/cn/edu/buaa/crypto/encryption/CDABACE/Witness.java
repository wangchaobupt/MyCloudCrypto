package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Witness {
    Sigma sigma;
    Element m, s;
    Map<String, Element> ris;
    Map<String, Element> tis;

    public Witness(Sigma sigma, Element m, Element s, Map<String, Element> ris, Map<String, Element> tis) {
        this.sigma = sigma;
        this.m = m;
        this.s = s;
        this.ris = ris;
        this.tis = tis;
    }
}
