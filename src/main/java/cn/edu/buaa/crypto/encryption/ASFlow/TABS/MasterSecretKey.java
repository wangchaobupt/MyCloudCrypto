package cn.edu.buaa.crypto.encryption.ASFlow.TABS;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class MasterSecretKey {
    public Element d0,d1,d2;
    public Map<String,Element> zx;
    public MasterSecretKey(Element d0,Element d1,Element d2,Map<String,Element> zx){
        this.d0 = d0;
        this.d1 = d1;
        this.d2 = d2;
        this.zx = zx;
    }
}
