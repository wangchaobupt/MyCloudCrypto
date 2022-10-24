package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import it.unisa.dia.gas.jpbc.Element;
public class CRS {
    public Element g,h,h1,h2;

    public CRS(Element g, Element h) {
        this.g = g;
        this.h = h;
    }

    public CRS(Element g, Element h,Element h1,Element h2) {
        this.g = g;
        this.h = h;
        this.h1 = h1;
        this.h2 = h2;
    }
}
