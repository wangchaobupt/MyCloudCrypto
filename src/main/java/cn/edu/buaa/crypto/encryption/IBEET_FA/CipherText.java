package cn.edu.buaa.crypto.encryption.IBEET_FA;

import it.unisa.dia.gas.jpbc.Element;
public class CipherText {
    public Element C1,C2,C4;
    byte[] C3,C5;
    public CipherText(Element c1,Element c2,Element c4,byte[] c3,byte[] c5){
        this.C1 = c1;
        this.C2 = c2;
        this.C3 = c3;
        this.C4 = c4;
        this.C5 = c5;
    }

    public int getlen(){
        return C1.toBytes().length + C2.toBytes().length + C3.length + C4.toBytes().length + C5.length;
    }
}
