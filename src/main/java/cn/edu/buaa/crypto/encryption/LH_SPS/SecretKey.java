package cn.edu.buaa.crypto.encryption.LH_SPS;

import it.unisa.dia.gas.jpbc.Element;
public class SecretKey {
    public Element hz_alpha;
    public Element[] xi,gamma,delta;
    public SecretKey(Element hz_alpha,Element[] xi,Element[] gamma,Element[] delta){
        this.delta = delta;
        this.hz_alpha = hz_alpha;
        this.xi = xi;
        this.gamma = gamma;
    }
}
