package cn.edu.buaa.crypto.encryption.P2GT_plus_new;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private cn.edu.buaa.crypto.encryption.P2GT_new.MasterSecretKey MK;
    private Element r;
    public MasterSecretKey(cn.edu.buaa.crypto.encryption.P2GT_new.MasterSecretKey msk, Element r){
        this.MK = msk;
        this.r = r;
    }

    public Element getR() {
        return r;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_new.MasterSecretKey getMK() {
        return MK;
    }
}
