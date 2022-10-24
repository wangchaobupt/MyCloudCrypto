package cn.edu.buaa.crypto.encryption.SPACE_part;

import cn.edu.buaa.crypto.encryption.CPSABE.CipherText;
import cn.edu.buaa.crypto.encryption.LH_SPS.PublicKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Statement {
    public PublicKey vk_s;
    public String[] A;
    public String accessPolicy;
    public Element[] M;
    public CipherText ct;
    public Pairing pairing;
    public Element P,Q;

    public Statement(Pairing pairing,PublicKey vk_s, String[] A, String accessPolicy,Element[] M, CipherText ct){
        this.pairing = pairing;
        this.vk_s = vk_s;
        this.A = A;
        this.accessPolicy = accessPolicy;
        this.M = M;
        this.ct = ct;
        this.Q = getQ();
        this.P = getP();
    }

    public Element getQ(){
        Element A = pairing.getGT().newOneElement().getImmutable();
        Element[] gi = vk_s.gi;
        for(int i=0;i<M.length;i++){
            A = A.mul(pairing.pairing(gi[i],M[i])).getImmutable();
        }
        return pairing.getGT().newOneElement().div(A).getImmutable();
    }

    public Element getP(){
        Element A = pairing.getGT().newOneElement().getImmutable();
        Element[] hi = vk_s.hi;
        for(int i=0;i<M.length;i++){
            A = A.mul(pairing.pairing(hi[i],M[i])).getImmutable();
        }
        return pairing.getGT().newOneElement().div(A).getImmutable();
    }
}
