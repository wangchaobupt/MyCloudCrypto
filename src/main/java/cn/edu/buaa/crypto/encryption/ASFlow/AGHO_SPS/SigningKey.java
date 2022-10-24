package cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS;
import it.unisa.dia.gas.jpbc.Element;
public class SigningKey {
    public Element beta,gamma;
    public Element[] z;

    public SigningKey(Element beta, Element gamma, Element[] z) {
        this.beta = beta;
        this.gamma = gamma;
        this.z = z;
    }
}
