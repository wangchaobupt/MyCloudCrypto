package cn.edu.buaa.crypto.encryption.DSFlow;

import cn.edu.buaa.crypto.encryption.AGHO_SPS.VerificationKey;

import it.unisa.dia.gas.jpbc.Element;

public class Statement {
    public VerificationKey vk;
    public Element C0,C,Q,P;
    public Statement(VerificationKey vk,Element C0,Element C,Element Q,Element P){
        this.C = C;
        this.C0 = C0;
        this.vk = vk;
        this.Q = Q;
        this.P = P;
    }
}
