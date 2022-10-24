package cn.edu.buaa.crypto.encryption.ASFlow.TABS;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class PublicKey {
    public Element g,g0,h1,h2;
    public Map<String,Element> Zx;
    public PublicKey(Element g,Element g0,Element h1,Element h2,Map<String,Element> Zx){
        this.g0 = g0;
        this.h1 = h1;
        this.h2 = h2;
        this.Zx = Zx;
        this.g = g;
    }
}
