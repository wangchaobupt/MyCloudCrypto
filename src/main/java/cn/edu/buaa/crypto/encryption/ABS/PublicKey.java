package cn.edu.buaa.crypto.encryption.ABS;

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;

public class PublicKey {
    public Element g,Y,T0;
    public Map<String,Element> Tx;
    public Element[] u;

    public PublicKey(Element g, Element Y, Element T0, Map<String,Element> Tx, Element[] u){
        this.g = g;
        this.Y = Y;
        this.T0 = T0;
        this.Tx = Tx;
        this.u = u;
    }
}
