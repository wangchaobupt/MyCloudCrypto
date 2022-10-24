package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class DK {
    Element K, L;
    Map<String, Element> K_x;

    public DK(Element k, Element l, Map<String, Element> k_x) {
        K = k;
        L = l;
        K_x = k_x;
    }
}
