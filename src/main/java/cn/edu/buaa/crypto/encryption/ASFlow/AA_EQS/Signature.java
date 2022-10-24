package cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS;
import it.unisa.dia.gas.jpbc.Element;
public class Signature {
    public Element Y0,Y1,Y2,Y3;

    public Signature(Element y0, Element y1, Element y2, Element y3) {
        Y0 = y0;
        Y1 = y1;
        Y2 = y2;
        Y3 = y3;
    }
}
