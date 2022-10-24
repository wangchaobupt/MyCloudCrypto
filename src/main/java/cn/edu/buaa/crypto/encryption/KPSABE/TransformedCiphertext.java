package cn.edu.buaa.crypto.encryption.KPSABE;

import it.unisa.dia.gas.jpbc.Element;

public class TransformedCiphertext {
    public Element C,B;
    public TransformedCiphertext(Element C, Element B){
        this.C = C;
        this.B = B;
    }

    public int getlen(){
        return B.toBytes().length + C.toBytes().length;
    }
}
