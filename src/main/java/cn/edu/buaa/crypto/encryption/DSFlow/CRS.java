package cn.edu.buaa.crypto.encryption.DSFlow;

import it.unisa.dia.gas.jpbc.Element;

public class CRS {
    public Element g0,h0,egg_gh0;
    public CRS(Element g0,Element h0,Element egg_gh0){
        this.g0 = g0;
        this.h0 = h0;
        this.egg_gh0 = egg_gh0;
    }
}
