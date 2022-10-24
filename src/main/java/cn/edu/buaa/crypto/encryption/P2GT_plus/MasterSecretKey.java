package cn.edu.buaa.crypto.encryption.P2GT_plus;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private cn.edu.buaa.crypto.encryption.P2GT_finall.MasterSecretKey msk;
    private Element r,u;
    public MasterSecretKey(cn.edu.buaa.crypto.encryption.P2GT_finall.MasterSecretKey msk, Element r, Element u){
        this.msk = msk;
        this.r = r;
        this.u = u;
    }

    public Element getR() {
        return r;
    }

    public Element getU() {
        return u;
    }

    public cn.edu.buaa.crypto.encryption.P2GT_finall.MasterSecretKey getMsk() {
        return msk;
    }
}
