package cn.edu.buaa.crypto.encryption.P2GT_plus_new;

import it.unisa.dia.gas.jpbc.Element;

public class PublicKey {
    public cn.edu.buaa.crypto.encryption.P2GT_new.PublicKey PK;
    public Element gr;
    public PublicKey(cn.edu.buaa.crypto.encryption.P2GT_new.PublicKey pk, Element gr){
        this.gr = gr;
        this.PK = pk;
    }
}
