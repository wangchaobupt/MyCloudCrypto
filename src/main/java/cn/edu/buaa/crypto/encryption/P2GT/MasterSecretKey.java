package cn.edu.buaa.crypto.encryption.P2GT;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    private  Element beta,ga;

    public MasterSecretKey(Element b, Element ga){
        this.beta = b;
        this.ga = ga;
    }

    public Element getBeta() {return this.beta;}

    public Element getGa() {return this.ga;}
}
