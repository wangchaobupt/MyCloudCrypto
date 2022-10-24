package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SigmaPrime {
    Map<String, Element> Rs;
    Map<String, Element> Ss;
    Map<String, Element> Ts;

    public SigmaPrime(Map<String, Element> rs, Map<String, Element> ss, Map<String, Element> ts) {
        Rs = rs;
        Ss = ss;
        Ts = ts;
    }
}
