package cn.edu.buaa.crypto.encryption.ABACEHAN;

import it.unisa.dia.gas.jpbc.Element;
public class SanSercetKey {
    private Element theta;
    public SanSercetKey(Element x){
        theta = x;
    }

    public Element getTheta() {
        return theta;
    }
}
