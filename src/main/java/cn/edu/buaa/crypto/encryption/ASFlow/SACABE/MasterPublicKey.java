package cn.edu.buaa.crypto.encryption.ASFlow.SACABE;
import it.unisa.dia.gas.jpbc.Element;
public class MasterPublicKey {
    public Element g,h,h1,h2,T1,T2;

    public MasterPublicKey(Element g, Element h, Element h1, Element h2, Element t1, Element t2) {
        this.g = g;
        this.h = h;
        this.h1 = h1;
        this.h2 = h2;
        T1 = t1;
        T2 = t2;
    }
}
