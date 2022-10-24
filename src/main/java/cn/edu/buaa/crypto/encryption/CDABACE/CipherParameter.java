package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherParameter {
    Map<String, Element> eks;
    Statement x;
    Proof pai;

    public CipherParameter(Map<String, Element> eks, Statement x, Proof pai) {
        this.eks = eks;
        this.x = x;
        this.pai = pai;
    }
}
