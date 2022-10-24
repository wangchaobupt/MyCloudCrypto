package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;

import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.PublicKey;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.VerficationKey;
import cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Map;

public class Statement {
    public PublicKey evk;
    public VerficationKey svk;
    public CipherText ct_rw;
    public cn.edu.buaa.crypto.encryption.ASFlow.SACABE.CipherText ct_ac;
    public String[] T, A, B;
    public Element[] Va;
    public Map<String, Element> Vb;
    public Element Q, P, R;

    // Statement-RW
    public Statement(PublicKey evk, VerficationKey svk, CipherText ct, String[] t, String[] b, String[] a, Element[] Va, Map<String, Element> Vb) {
        this.evk = evk;
        this.svk = svk;
        this.ct_rw = ct;
        T = t;
        B = b;
        A = a;
        this.Va = Va;
        this.Vb = Vb;
    }

    // Statement-AC
    public Statement(PublicKey evk, VerficationKey svk, cn.edu.buaa.crypto.encryption.ASFlow.SACABE.CipherText ct, String[] t, String[] b, String[] a, Element[] Va, Map<String, Element> Vb) {
        this.evk = evk;
        this.svk = svk;
        this.ct_ac = ct;
        T = t;
        B = b;
        A = a;
        this.Va = Va;
        this.Vb = Vb;
    }


    public void init(Pairing pairing, Element g, Element h) {
        P = pairing.pairing(g, h).getImmutable();
        Element D = pairing.getGT().newOneElement().getImmutable();
        Element[] U = svk.U;
        for (int i = 0; i < A.length; i++) {
            D = D.mul(pairing.pairing(Va[i], U[i])).getImmutable();
        }
        Q = pairing.pairing(g, svk.W).div(D).getImmutable();
        R = pairing.getGT().newOneElement().getImmutable();
        for (String att : B) {
            R = R.mul(pairing.pairing(Vb.get(att), evk.Zx.get(att))).getImmutable();
        }
    }
}
