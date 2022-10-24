package cn.edu.buaa.crypto.encryption.AGHO_SPS;

import it.unisa.dia.gas.jpbc.Element;
public class VerificationKey {
    public Element[] U;
    public Element V,Z;
    public VerificationKey(Element[] U,Element V,Element Z){
        this.U = U;
        this.V = V;
        this.Z = Z;
    }
}
