package cn.edu.buaa.crypto.encryption.P2GT_plus;

import it.unisa.dia.gas.jpbc.Element;
public class PublicKey {
    public cn.edu.buaa.crypto.encryption.P2GT_finall.PublicKey pk;
    public Element ur,gu;
    public PublicKey(cn.edu.buaa.crypto.encryption.P2GT_finall.PublicKey pk,Element u,Element g){
        this.pk = pk;
        this.gu = g;
        this.ur = u;
    }
}
