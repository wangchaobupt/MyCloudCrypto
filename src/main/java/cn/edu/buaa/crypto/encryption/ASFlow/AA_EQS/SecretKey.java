package cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SecretKey {
    public Map<String,Element> zx;
    public SecretKey(Map<String,Element> zx){
        this.zx = zx;
    }
}
