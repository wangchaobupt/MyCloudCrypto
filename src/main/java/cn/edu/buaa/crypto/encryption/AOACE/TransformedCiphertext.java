package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;
public class TransformedCiphertext {
    public Element C,Y1,Y2;
    public TransformedCiphertext(Element C,Element Y1,Element Y2){
        this.C = C;
        this.Y1 = Y1;
        this.Y2 = Y2;
    }
}
