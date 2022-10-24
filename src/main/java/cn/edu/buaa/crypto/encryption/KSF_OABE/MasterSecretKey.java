package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private Element x;
    public MasterSecretKey(Element x){
        this.x = x;
    }

    public Element getX() {
        return x;
    }
}
