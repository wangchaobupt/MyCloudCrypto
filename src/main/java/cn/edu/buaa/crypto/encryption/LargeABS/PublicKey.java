package cn.edu.buaa.crypto.encryption.LargeABS;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class PublicKey {
    public Element g,Y;
    public Element[] Vx;
    public Element[] u;
    public PublicKey(Element g,Element Y,Element[] Vx,Element[] u){
        this.g = g;
        this.Y = Y;
        this.Vx = Vx;
        this.u = u;
    }
}
