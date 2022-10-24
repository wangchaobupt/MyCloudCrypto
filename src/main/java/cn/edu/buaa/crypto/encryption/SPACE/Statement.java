package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.encryption.CPSABE.CipherText;
import cn.edu.buaa.crypto.encryption.LH_SPS.PublicKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.awt.event.ActionListener;

public class Statement {
    public PublicKey vk_s,vk_o;
    public String[] A,W;
    public String accessPolicy;
    public Element[] M,O;
    public CipherText ct;
    public Pairing pairing;
    public SignParameter sigma_w;
    public Element P,Q,P1;

    public Statement(Pairing pairing,PublicKey vk_s,PublicKey vk_o, String[] A, String[] W, String accessPolicy,Element[] M,Element[] O,
                     CipherText ct,SignParameter sigma_w){
        this.pairing = pairing;
        this.vk_o = vk_o;
        this.vk_s = vk_s;
        this.A = A;
        this.W = W;
        this.accessPolicy = accessPolicy;
        this.M = M;
        this.O = O;
        this.ct = ct;
        this.sigma_w = sigma_w;
        this.Q = getQ();
        this.P = getP();
        this.P1 = getP1();
    }

    public void  setPairing(Pairing pairing){
        this.pairing = pairing;
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

    public Element getP1(){
        Element A = pairing.getGT().newOneElement().getImmutable();
        Element[] hi = vk_o.hi;
        for(int i=0;i<O.length;i++){
            A = A.mul(pairing.pairing(hi[i],O[i])).getImmutable();
        }

        Element B = pairing.pairing(vk_o.hz,sigma_w.Z).mul(pairing.pairing(vk_o.h,sigma_w.U)).getImmutable();
        return pairing.getGT().newOneElement().div(A).div(B).getImmutable();
    }
}
