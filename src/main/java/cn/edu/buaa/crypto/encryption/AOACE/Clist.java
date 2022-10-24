package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Clist implements Serializable {
    public Map<String, byte[]> bCs1,bCs2,bCs3;
    public Clist(Map<String, Element> Cs1, Map<String, Element> Cs2, Map<String, Element> Cs3){
        bCs1 = new HashMap<String, byte[]>();
        for(String att : Cs1.keySet()){
            bCs1.put(att, Cs1.get(att).toBytes());
        }
        bCs2 = new HashMap<String, byte[]>();
        for(String att : Cs2.keySet()){
            bCs2.put(att, Cs2.get(att).toBytes());
        }
        bCs3 = new HashMap<String, byte[]>();
        for(String att : Cs3.keySet()){
            bCs3.put(att, Cs3.get(att).toBytes());
        }
    }

    public Map<String, Element> getMap(Map<String, byte[]> data, Pairing pairing){
        Map<String, Element> res = new HashMap<String, Element>();
        for(String att : data.keySet()){
            res.put(att, pairing.getG1().newElementFromBytes(data.get(att)));
        }
        return res;
    }
}
