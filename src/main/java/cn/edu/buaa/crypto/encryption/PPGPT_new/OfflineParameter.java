package cn.edu.buaa.crypto.encryption.PPGPT_new;

import it.unisa.dia.gas.jpbc.Element;

import java.util.List;

public class OfflineParameter {
    private Element R,R1;
    private Element Y;
    private List<Element> k;
    public OfflineParameter(Element r,Element r1,Element y,List<Element> k){
        this.k = k;
        this.R = r;
        this.R1 = r1;
        this.Y = y;
    }

    public Element getR() {
        return R;
    }

    public Element getR1() {
        return R1;
    }

    public Element getY() {
        return Y;
    }

    public List<Element> getK() {
        return k;
    }

    public int getlen(){
        int len = R.toBytes().length + R1.toBytes().length + Y.toBytes().length;
        for(int i=0;i<k.size();i++) len+=k.get(i).toBytes().length;
        return len;
    }

}
