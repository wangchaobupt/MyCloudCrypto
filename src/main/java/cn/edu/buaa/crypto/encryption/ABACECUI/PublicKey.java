package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;

public class PublicKey {
    Element[] h3,h4;
    Element T3,h5;
    public PublicKey(Element T3,Element[] h3,Element[] h4,Element h5){
        this.T3 = T3;
        this.h3 = h3;
        this.h4 = h4;
        this.h5 = h5;
    }
}
