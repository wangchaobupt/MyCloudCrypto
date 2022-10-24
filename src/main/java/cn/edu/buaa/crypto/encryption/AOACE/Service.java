package cn.edu.buaa.crypto.encryption.AOACE;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import it.unisa.dia.gas.jpbc.Element;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class Service {
    public static Pairing pairing = PairingFactory.getPairing("params/SS768.properties");
    public static Element getsum_F(Flist flist){
        Element E1 = flist.getElement(flist.bE1,pairing);
        Element g = flist.getElement(flist.bg,pairing);
        Element h = flist.getElement(flist.bh,pairing);
        Element u = flist.getElement(flist.bu,pairing);
        Element v = flist.getElement(flist.bv,pairing);
        Element w = flist.getElement(flist.bw,pairing);
        Map<String, Element> Es2 = flist.getMap(flist.bEs2,pairing);
        Map<String, Element> Es3 = flist.getMap(flist.bEs3,pairing);
        Map<String, Element> mus = flist.getMap_Z(flist.bmus,pairing);
        Map<String, Element> w_i = flist.getMap_Z(flist.bomega,pairing);

        Map<String, Element> Ts1 = new HashMap<String, Element>();
        Map<String, Element> Ts2 = new HashMap<String, Element>();
        Map<String, Element> Ts3 = new HashMap<String, Element>();

        for (String rho : mus.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ki = pairing.getZr().newRandomElement().getImmutable();
            Ts1.put(rho, w.powZn(mus.get(rho)).mul(v.powZn(ki)).getImmutable());
            Ts2.put(rho, (u.powZn(elementRho).mul(h)).powZn(ki.negate()).getImmutable());
            Ts3.put(rho, g.powZn(ki));
        }

        Element sumF = pairing.getGT().newOneElement().getImmutable();
        for (String att : w_i.keySet()) {
            Element tmp = pairing.pairing(Ts1.get(att),E1).mul(pairing.pairing(Ts2.get(att),Es2.get(att)))
                    .mul(pairing.pairing(Ts3.get(att),Es3.get(att))).powZn(w_i.get(att)).getImmutable();
            sumF = sumF.mul(tmp).getImmutable();
        }
        System.out.println("sumF:"+sumF);
        return sumF;
    }

    public static Clist getsum_B(Blist blist){
        Element g = blist.getElement(blist.bg,pairing);
        Element h = blist.getElement(blist.bh,pairing);
        Element u = blist.getElement(blist.bu,pairing);
        Element v = blist.getElement(blist.bv,pairing);
        Element w = blist.getElement(blist.bw,pairing);
        Map<String, Element> Ci1 = blist.getMap(blist.bCs1,pairing);
        Map<String, Element> Ci2 = blist.getMap(blist.bCs2,pairing);
        Map<String, Element> Ci3 = blist.getMap(blist.bCs3,pairing);
        Map<String, Element> mus = blist.getMap_Z(blist.bmus,pairing);

        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();

        for (String rho : mus.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element di = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho, Ci1.get(rho).mul(w.powZn(mus.get(rho))).mul(v.powZn(di)).getImmutable());
            Cs2.put(rho, Ci2.get(rho).mul((u.powZn(elementRho).mul(h)).powZn(di.negate())).getImmutable());
            Cs3.put(rho, Ci3.get(rho).mul(g.powZn(di)).getImmutable());
        }

        Clist clist = new Clist(Cs1,Cs2,Cs3);
        return clist;
    }

    public static void main(String[] args) throws Exception {

        ServerSocket socketConnection = new ServerSocket(8888);
        System.out.println("wait");
        try{
            while (true){
                Socket scoket = socketConnection.accept();
                ObjectInputStream in = new ObjectInputStream(scoket.getInputStream());
                ObjectOutputStream out = new ObjectOutputStream(scoket.getOutputStream());
                int type = in.read();
                System.out.println("type:"+type);
                if(type == 1){
                    Flist flist = (Flist) in.readObject();
                    Element sumF = getsum_F(flist);
                    byte[] bF = sumF.toBytes();
                    out.write(bF);
                    out.flush();
                }else if(type == 2){
                    Blist blist = (Blist) in.readObject();
                    Clist clist = getsum_B(blist);
                    out.writeObject(clist);
                    out.flush();
                }

                out.close();
                in.close();
            }
        }finally {
            socketConnection.close();
        }

    }

}
