package cn.edu.buaa.crypto.encryption.CDABACE;

import it.unisa.dia.gas.jpbc.Element;

public class PP_sa {
    CRS crs;
    Element X;
    Element vk;

    public PP_sa(CRS crs, Element x, Element vk) {
        this.crs = crs;
        X = x;
        this.vk = vk;
    }
}
