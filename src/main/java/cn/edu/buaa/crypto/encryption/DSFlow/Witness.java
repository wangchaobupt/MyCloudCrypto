package cn.edu.buaa.crypto.encryption.DSFlow;

import cn.edu.buaa.crypto.encryption.AGHO_SPS.Signature;

import it.unisa.dia.gas.jpbc.Element;

public class Witness {
    public Signature sign;
    public Element m,s;
    public Witness(Signature sign,Element m,Element s){
        this.s = s;
        this.m = m;
        this.sign = sign;
    }
}
