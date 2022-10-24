package cn.edu.buaa.crypto.encryption.ABS;

import it.unisa.dia.gas.jpbc.Element;

public class SignParameter {
    public Element sigma1,sigma2,sigma3;
    public SignParameter(Element sigma1, Element sigma2, Element sigma3){
        this.sigma1 = sigma1;
        this.sigma2 = sigma2;
        this.sigma3 = sigma3;
    }

}
