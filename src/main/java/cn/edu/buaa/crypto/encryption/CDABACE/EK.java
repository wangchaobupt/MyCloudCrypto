package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class EK {
    public String accessPolicy;
    public Map<String, Element> eks;
    public Sigma sigma;

    public EK(String accessPolicy, Map<String, Element> eks, Sigma sigma) {
        this.accessPolicy = accessPolicy;
        this.eks = eks;
        this.sigma = sigma;
    }
}
