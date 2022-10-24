package cn.edu.buaa.crypto.encryption.IBEET_FA;

import it.unisa.dia.gas.jpbc.Element;
public class DecryptionKey {
    private Element dk1,dk2;
    public DecryptionKey(Element dk1,Element dk2){
        this.dk1 = dk1;
        this.dk2 = dk2;
    }

    public Element getDk2() {
        return dk2;
    }

    public Element getDk1() {
        return dk1;
    }

    public int getlen(){
        return dk2.toBytes().length + dk1.toBytes().length;
    }
}
