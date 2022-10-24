package cn.edu.buaa.crypto.encryption.AGHO_SPS;

import it.unisa.dia.gas.jpbc.Element;
public class Signature {
    public Element R,W,T;
    public Signature(Element R,Element W,Element T){
        this.R = R;
        this.W = W;
        this.T = T;
    }
}
