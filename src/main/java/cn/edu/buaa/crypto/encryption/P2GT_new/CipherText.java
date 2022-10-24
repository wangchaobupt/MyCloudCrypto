package cn.edu.buaa.crypto.encryption.P2GT_new;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CipherText {
    public String[] Y;
    public String[] Z;
    public byte[] C0;
    public Element C1,C2,E0;
    public Map<String, Element> Cs0,Cs1,Es0,Es1;
    public Element[] Ei0,Ei1;
    public byte[][] pID;
    public CipherText(String[] y, String[] z, byte[] c0, Element c1, Element c2, Map<String, Element> cs0, Map<String, Element> cs1, Element e0, Element[] ei0,Element[] ei1,Map<String, Element> es0,Map<String, Element> es1,byte[][] pID){
        this.Y = y;
        this.Z = z;
        this.C0 = c0;
        this.C1 = c1;
        this.C2 = c2;
        this.Cs0 = cs0;
        this.Cs1 = cs1;
        this.E0 = e0;
        this.Ei0 = ei0;
        this.Ei1 = ei1;
        this.Es0 = es0;
        this.Es1 = es1;
        this.pID = pID;
    }

    public int getlen(){
        int len = C0.length + C1.toBytes().length + C2.toBytes().length + E0.toBytes().length;
        for(int i=0;i<Y.length;i++) len+=Y[i].length();
        for(int i=0;i<Z.length;i++) len+=Z[i].length();
        for(int i=0;i<Ei0.length;i++) len+=Ei0[i].toBytes().length;
        for(int i=0;i<Ei1.length;i++) len+=Ei1[i].toBytes().length;
        for(int i=0;i<pID.length;i++) len+=pID[i].length;

        for(Map.Entry<String,Element> entry : Cs0.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : Cs1.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : Es0.entrySet()){
            len += entry.getKey().length() + entry.getValue().toBytes().length;
        }
        for(Map.Entry<String,Element> entry : Es1.entrySet()){
            len += entry.getKey().length() + entry.
                    getValue().toBytes().length;
        }
        return len;
    }

}
