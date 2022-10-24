package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;

public class SignatureKey {
    public Element alpha;
    public Element[] g2_c1,g2_c2;
    public SignatureKey(Element a, Element[] g2_c1,Element[] g2_c2){
        this.alpha = a;
        this.g2_c1 = g2_c1;
        this.g2_c2 = g2_c2;
    }
}
