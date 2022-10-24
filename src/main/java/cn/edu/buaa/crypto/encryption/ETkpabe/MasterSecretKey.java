package cn.edu.buaa.crypto.encryption.ETkpabe;

import it.unisa.dia.gas.jpbc.Element;
public class MasterSecretKey {
    private Element[] x;
    private Element y1,y2;
    public MasterSecretKey(Element[] x,Element y1,Element y2){
        this.x = x;
        this.y1 = y1;
        this.y2 = y2;
    }

    public Element getY1() {
        return y1;
    }

    public Element getY2() {
        return y2;
    }

    public Element[] getX() {
        return x;
    }
}
