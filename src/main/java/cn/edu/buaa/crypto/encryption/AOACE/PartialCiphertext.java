package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;

public class PartialCiphertext {
    public IntermediateCiphertext it;
    public Element K0,L0,L1;
    public Map<String, Element> Ls2,Ls3;
    public PartialCiphertext(IntermediateCiphertext it,Element K0,Element L0,Element L1,Map<String, Element> Ls2,Map<String, Element> Ls3){
        this.it = it;
        this.K0 = K0;
        this.L0 = L0;
        this.L1 = L1;
        this.Ls2 = Ls2;
        this.Ls3 = Ls3;
    }
}
