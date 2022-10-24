package cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS;
import it.unisa.dia.gas.jpbc.Element;
public class VerficationKey {
    public Element V,W;
    public Element[] U;

    public VerficationKey(Element v, Element w, Element[] u) {
        V = v;
        W = w;
        U = u;
    }
}
