package cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class PublicKey {
    public Map<String,Element> Zx;
    public PublicKey(Map<String,Element> Zx){
        this.Zx = Zx;
    }
}
