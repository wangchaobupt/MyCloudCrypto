package cn.edu.buaa.crypto.encryption.Socket;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class Flist implements Serializable {
//    public Element g;
//    public Map<String, Element> Cs1;
    public byte[] bg;
    public Map<String, byte[]> bCs1;

    public Flist(Element g,Map<String, Element> Cs1){
        bg = g.toBytes();
        bCs1 = new HashMap<String, byte[]>();
        for(String i : Cs1.keySet()){
            bCs1.put(i,Cs1.get(i).toBytes());
        }
    }
//    public Flist(byte[] g,Map<String, byte[]> Cs1){
//        this.g = g;
//        this.Cs1 = Cs1;
//    }
    public Element getG(Pairing pairing){
        return pairing.getG1().newElementFromBytes(bg);
    }

    public Map<String ,Element> getCs1(Pairing pairing){
        Map<String ,Element> res = new HashMap<String, Element>();
        for(String att : bCs1.keySet()){
            res.put(att, pairing.getG1().newElementFromBytes(bCs1.get(att)));
        }
        return res;
    }
}
