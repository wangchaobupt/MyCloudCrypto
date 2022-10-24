package cn.edu.buaa.crypto.encryption.SPACE_part;

import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;

public class Witness {
    public Element m;
    public SignParameter sigma_A;
    public Element s;

    public Witness(Element m,SignParameter sigma_A,Element s){
        this.m = m;
        this.s = s;
        this.sigma_A = sigma_A;
    }
}
