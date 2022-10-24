package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class Statement {
    SigmaPrime sigmaPrime;
    CipherData ct;
    Map<String, Element> Qs;
    Map<String, Element> eks;

    public Statement(SigmaPrime sigmaPrime, CipherData ct, Map<String, Element> qs,  Map<String, Element> eks) {
        this.ct = ct;
        this.sigmaPrime = sigmaPrime;
        this.Qs = qs;
        this.eks = eks;
    }
}
