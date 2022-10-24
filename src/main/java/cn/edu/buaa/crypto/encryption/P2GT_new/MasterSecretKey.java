package cn.edu.buaa.crypto.encryption.P2GT_new;

import it.unisa.dia.gas.jpbc.Element;
public class MasterSecretKey {
    private Element a;
    public MasterSecretKey(Element a){
        this.a = a;
    }

    public Element getA() {
        return a;
    }
}
