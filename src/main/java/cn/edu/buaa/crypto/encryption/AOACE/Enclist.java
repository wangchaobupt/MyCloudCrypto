package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Enclist implements Serializable {
    public byte[] bw,bv,bu,bh,bg,br;
    public Map<String, byte[]> bKs2,bKs3;
    public Enclist(Map<String, Element> Ks2, Map<String, Element> Ks3,
                   Element w, Element v, Element u, Element h, Element g,Element r){
        bw = w.toBytes();
        bv = v.toBytes();
        bh = h.toBytes();
        bg = g.toBytes();
        bu = u.toBytes();
        br = r.toBytes();
        bKs2 = new HashMap<String, byte[]>();
        for(String att : Ks2.keySet()){
            bKs2.put(att, Ks2.get(att).toBytes());
        }
        bKs3 = new HashMap<String, byte[]>();
        for(String att : Ks3.keySet()){
            bKs2.put(att, Ks3.get(att).toBytes());
        }
    }
    public Element getElement(byte[] data, Pairing pairing){
        return pairing.getG1().newElementFromBytes(data).getImmutable();
    }

    public Element getElement_Z(byte[] data, Pairing pairing){
        return pairing.getZr().newElementFromBytes(data).getImmutable();
    }
    public Map<String, Element> getMap(Map<String, byte[]> data, Pairing pairing){
        Map<String, Element> res = new HashMap<String, Element>();
        for(String att : data.keySet()){
            res.put(att, pairing.getG1().newElementFromBytes(data.get(att)));
        }
        return res;
    }
}
