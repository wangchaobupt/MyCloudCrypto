package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SignParameter {
    public Element m;
    public String[] B;
    public Map<String,Element> V;
    public Signature sign;

    public SignParameter(Element m, String[] b, Signature sign,Map<String,Element> V) {
        this.m = m;
        B = b;
        this.sign = sign;
        this.V = V;
    }
}
