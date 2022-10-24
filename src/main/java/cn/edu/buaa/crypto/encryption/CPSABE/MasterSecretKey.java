package cn.edu.buaa.crypto.encryption.CPSABE;

import it.unisa.dia.gas.jpbc.Element;

public class MasterSecretKey {
    public Element alpha;
    public MasterSecretKey(Element alpha){
        this.alpha = alpha;
    }
}
