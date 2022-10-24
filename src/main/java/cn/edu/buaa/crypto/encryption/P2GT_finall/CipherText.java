package cn.edu.buaa.crypto.encryption.P2GT_finall;

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;

public class CipherText {
    public String[] Y;
    public String[] Z;
    public byte[] C0;
    public Element C1,C2,C3;
    public Map<String, Element> Cy;
    public Map<String, Element> Cz;
    public Element[] E1,E2;
    public byte[][] pID;
    public CipherText(String[] y, String[] z, byte[] c0, Element c1, Element c2,Element c3,Map<String, Element> cy,Map<String, Element> cz,Element[] e1,Element[] e2,byte[][] pID){
        this.Y = y;
        this.Z = z;
        this.C0 = c0;
        this.C1 = c1;
        this.C2 = c2;
        this.C3 = c3;
        this.Cy = cy;
        this.Cz = cz;
        this.E1 = e1;
        this.E2 = e2;
        this.pID = pID;
    }

    public byte[] getC0() {
        return C0;
    }

    public Element getC1() {
        return C1;
    }

    public Element getC2() {
        return C2;
    }

    public Element getC3() {
        return C3;
    }

    public Element[] getE1() {
        return E1;
    }

    public Element[] getE2() {
        return E2;
    }

    public String[] getY() {
        return Y;
    }

    public String[] getZ() {
        return Z;
    }

    public byte[][] getpID() {
        return pID;
    }

    public Map<String, Element> getCy() {
        return Cy;
    }

    public Map<String, Element> getCz() {
        return Cz;
    }
}
