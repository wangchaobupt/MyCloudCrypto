package cn.edu.buaa.crypto.encryption.AGHO_SPS;

import it.unisa.dia.gas.jpbc.Element;
public class SigningKey {
    public Element[] u;
    public Element v,z;
    public SigningKey(Element[] u, Element v,Element z){
        this.u = u;
        this.v = v;
        this.z = z;
    }
}
