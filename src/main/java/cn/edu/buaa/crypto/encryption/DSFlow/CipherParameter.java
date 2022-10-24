package cn.edu.buaa.crypto.encryption.DSFlow;

import cn.edu.buaa.crypto.encryption.KPSABE.CipherText;

import it.unisa.dia.gas.jpbc.Element;

public class CipherParameter {
    public CipherText ct;
    public Proof proof;
    public Element[] M;
    public CipherParameter(CipherText ct,Proof proof,Element[] M){
        this.ct = ct;
        this.proof = proof;
        this.M = M;
    }

    public int getlen(){
        int len = ct.getlen() + proof.getlen();
        for(int i=0;i<M.length;i++){
            len += M[i].toBytes().length;
        }
        return len;
    }
}
