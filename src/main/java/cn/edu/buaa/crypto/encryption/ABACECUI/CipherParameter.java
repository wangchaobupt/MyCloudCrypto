package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;

public class CipherParameter {
    public CipherText ct;
    public PublicKey pk;
    public String[] As,Ar;
    public Element[] theta;
    public String accessPolicy,T;
    public CipherParameter(CipherText ct,PublicKey pk,String T,String[] As,String[] Ar,Element[] theta,String accessPolicy){
        this.pk = pk;
        this.ct = ct;
        this.As = As;
        this.Ar = Ar;
        this.theta = theta;
        this.accessPolicy = accessPolicy;
        this.T = T;
    }
}
