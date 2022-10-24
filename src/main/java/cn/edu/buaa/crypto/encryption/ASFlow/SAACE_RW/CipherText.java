package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import cn.edu.buaa.crypto.encryption.ASFlow.TABS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText ct_rw;
    public cn.edu.buaa.crypto.encryption.ASFlow.SACABE.CipherText ct_ac;
    public PList P;
    public String[] B;
    public Element[] Va;
    public Map<String,Element> Vb;
    public SignParameter sign;

    public CipherText(cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText ct, PList p, String[] b, Element[] va, Map<String, Element> vb, SignParameter sign) {
        this.ct_rw = ct;
        P = p;
        B = b;
        Va = va;
        Vb = vb;
        this.sign = sign;
    }

    public CipherText(cn.edu.buaa.crypto.encryption.ASFlow.SACABE.CipherText ct, PList p, String[] b, Element[] va, Map<String, Element> vb, SignParameter sign) {
        this.ct_ac = ct;
        P = p;
        B = b;
        Va = va;
        Vb = vb;
        this.sign = sign;
    }
}
