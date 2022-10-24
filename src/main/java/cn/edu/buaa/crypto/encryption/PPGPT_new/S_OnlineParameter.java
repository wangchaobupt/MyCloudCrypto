package cn.edu.buaa.crypto.encryption.PPGPT_new;

import it.unisa.dia.gas.jpbc.Element;
import java.util.List;

public class S_OnlineParameter {
    private Element Y;
    private List<Element> ts;
    private List<Element> al;
    public S_OnlineParameter(Element y, List<Element> a,List<Element> ts){
        this.Y = y;
        this.ts = ts;
        this.al = a;
    }

    public Element getY() {
        return Y;
    }

    public List<Element> getTs() {
        return ts;
    }

    public List<Element> getAl() {
        return al;
    }

    public int getlen(){
        int len = Y.toBytes().length;
        for(int i=0;i<ts.size();i++) len+=ts.get(i).toBytes().length;
        for(int i=0;i<al.size();i++) len+=al.get(i).toBytes().length;
        return len;
    }
}
