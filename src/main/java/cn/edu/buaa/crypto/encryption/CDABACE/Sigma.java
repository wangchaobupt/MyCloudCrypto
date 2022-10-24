package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Sigma {
    Element R;
    Map<String, Element> Ss;
    Map<String, Element> Ts;
    Element W;

    public Sigma(Element r, Map<String, Element> ss, Map<String, Element> ts, Element W) {
        R = r;
        Ss = ss;
        Ts = ts;
        this.W = W;
    }
}
