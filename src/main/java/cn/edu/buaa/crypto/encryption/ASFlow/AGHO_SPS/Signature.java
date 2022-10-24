package cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS;
import it.unisa.dia.gas.jpbc.Element;
public class Signature {
    public Element X0,X1,X2,X3;

    public Signature(Element x0, Element x1, Element x2, Element x3) {
        X0 = x0;
        X1 = x1;
        X2 = x2;
        X3 = x3;
    }
}
