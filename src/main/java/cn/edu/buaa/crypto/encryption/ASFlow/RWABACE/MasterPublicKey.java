package cn.edu.buaa.crypto.encryption.ASFlow.RWABACE;
import it.unisa.dia.gas.jpbc.Element;
public class MasterPublicKey {
    public Element g,u,h,w,v,egh_alpha;

    public MasterPublicKey(Element g, Element u, Element h, Element w, Element v, Element egh_alpha) {
        this.g = g;
        this.u = u;
        this.h = h;
        this.w = w;
        this.v = v;
        this.egh_alpha = egh_alpha;
    }
}
