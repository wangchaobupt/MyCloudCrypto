package cn.edu.buaa.crypto.encryption.ASFlow.TABS;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class SignKey {
    public Map<String,Element> Dx;
    public SignKey(Map<String,Element> Dx){
        this.Dx = Dx;
    }
}
