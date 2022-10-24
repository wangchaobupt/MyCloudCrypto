package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Flist implements Serializable {
    public byte[] bE1,bw,bv,bu,bh,bg;
    public Map<String, byte[]> bEs2,bEs3,bmus,bomega;
    public Flist(Element E1, Map<String, Element> Es2, Map<String, Element> Es3, Map<String, Element> mus, Map<String, Element> omegaElementsMap,
                 Element w, Element v, Element u, Element h, Element g){
        bE1 = E1.toBytes();
        bw = w.toBytes();
        bv = v.toBytes();
        bh = h.toBytes();
        bg = g.toBytes();
        bu = u.toBytes();
        bEs2 = new HashMap<String, byte[]>();
        for(String att : Es2.keySet()){
            bEs2.put(att, Es2.get(att).toBytes());
        }
        bEs3 = new HashMap<String, byte[]>();
        for(String att : Es3.keySet()){
            bEs3.put(att, Es3.get(att).toBytes());
        }
        bmus = new HashMap<String, byte[]>();
        for(String att : mus.keySet()){
            bmus.put(att, mus.get(att).toBytes());
        }
        bomega = new HashMap<String, byte[]>();
        for(String att : omegaElementsMap.keySet()){
            bomega.put(att, omegaElementsMap.get(att).toBytes());
        }
    }

    public Element getElement(byte[] data,Pairing pairing){
        return pairing.getG1().newElementFromBytes(data).getImmutable();
    }

    public Map<String, Element> getMap(Map<String, byte[]> data, Pairing pairing){
        Map<String, Element> res = new HashMap<String, Element>();
        for(String att : data.keySet()){
            res.put(att, pairing.getG1().newElementFromBytes(data.get(att)));
        }
        return res;
    }

    public Map<String, Element> getMap_Z(Map<String, byte[]> data, Pairing pairing){
        Map<String, Element> res = new HashMap<String, Element>();
        for(String att : data.keySet()){
            res.put(att, pairing.getZr().newElementFromBytes(data.get(att)));
        }
        return res;
    }
}
