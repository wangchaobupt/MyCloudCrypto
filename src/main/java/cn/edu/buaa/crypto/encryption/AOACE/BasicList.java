package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.Serializable;

public class BasicList implements Serializable {
    public byte[] bw,bv,bu,bh,bg;
    public BasicList(Element w, Element v, Element u, Element h, Element g){
        bw = w.toBytes();
        bv = v.toBytes();
        bh = h.toBytes();
        bg = g.toBytes();
        bu = u.toBytes();
    }

    public Element getElement(byte[] data, Pairing pairing){
        return pairing.getG1().newElementFromBytes(data).getImmutable();
    }
}
