package cn.edu.buaa.crypto.encryption.SABE;

import it.unisa.dia.gas.jpbc.Element;
public class MasterSecretKey {
    public Element g_alpha,g_beta;
    public MasterSecretKey(Element g_alpha,Element g_beta){
        this.g_alpha = g_alpha;
        this.g_beta = g_beta;
    }
}
