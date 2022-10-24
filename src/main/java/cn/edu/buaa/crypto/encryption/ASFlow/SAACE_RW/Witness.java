package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.Signature;
import it.unisa.dia.gas.jpbc.Element;
public class Witness {
    public Element m,s;
    public Element s1,s2;
    public Signature mu;
    public cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature eta;

    public Witness(Element m, Element s, Signature mu, cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature eta) {
        this.m = m;
        this.s = s;
        this.mu = mu;
        this.eta = eta;
    }

    public Witness(Element m, Element s1, Element s2,Signature mu, cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature eta) {
        this.m = m;
        this.s1 = s1;
        this.s2 = s2;
        this.mu = mu;
        this.eta = eta;
    }
}
