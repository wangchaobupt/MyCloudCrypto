package cn.edu.buaa.crypto.encryption.PPGCT;

import it.unisa.dia.gas.jpbc.Element;
import java.util.List;

public class C_OnlineParameter {
    private Element[] rc;
    private List<Element> a;
    public C_OnlineParameter(Element[] r,List<Element> a){
        this.a = a;
        this.rc = r;
    }

    public Element[] getRc() {
        return rc;
    }

    public List<Element> getA() {
        return a;
    }

    public int getlen(){
        int len = 0;
        for(int i=0;i<rc.length;i++) len+=rc[i].toBytes().length;
        for(int i=0;i<a.size();i++) len+=a.get(i).toBytes().length;
        return len;
    }
}
