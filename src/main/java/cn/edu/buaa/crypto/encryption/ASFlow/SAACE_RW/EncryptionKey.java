package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;

import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.Signature;
import cn.edu.buaa.crypto.encryption.ASFlow.TABS.SignKey;

import it.unisa.dia.gas.jpbc.Element;

public class EncryptionKey {
    public Signature sign;
    public SignKey ak;
    public PList P;
    public Element[] V;

    public EncryptionKey(Signature sign, SignKey ak, PList p, Element[] v) {
        this.sign = sign;
        this.ak = ak;
        P = p;
        V = v;
    }
}
