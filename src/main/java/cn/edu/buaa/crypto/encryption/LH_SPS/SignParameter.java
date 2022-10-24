package cn.edu.buaa.crypto.encryption.LH_SPS;

import it.unisa.dia.gas.jpbc.Element;
public class SignParameter {
    public Element Z,R,U,V;
    public SignParameter(Element z,Element r,Element u,Element v){
        Z = z;
        R = r;
        U = u;
        V = v;
    }
}
