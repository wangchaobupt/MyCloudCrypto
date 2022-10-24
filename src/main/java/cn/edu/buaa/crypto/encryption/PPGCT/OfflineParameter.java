package cn.edu.buaa.crypto.encryption.PPGCT;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class OfflineParameter {
    private Element Rs;
    private List<Element> ts;
    public OfflineParameter(Element rs,List<Element> ts){
        this.Rs = rs;
        this.ts = ts;
    }

    public Element getRs() {
        return Rs;
    }

    public List<Element> getTs() {
        return ts;
    }

    public int getlen(){
        int len = Rs.toBytes().length;
        for(int i=0;i<ts.size();i++) len+=ts.get(i).toBytes().length;
        return len;
    }
}
