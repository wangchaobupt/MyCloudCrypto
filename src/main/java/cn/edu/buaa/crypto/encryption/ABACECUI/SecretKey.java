package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Map;

public class SecretKey {
    ArrayList<Element> sk0,sk_1;
    Map<String, ArrayList<Element>> sk_y;
    SignatureKey sk_th;
    String[] attributes;
    public SecretKey(ArrayList<Element> sk0,Map<String, ArrayList<Element>> sk_y,ArrayList<Element> sk_1,SignatureKey sk_th,String[] attributes){
        this.sk0 = sk0;
        this.sk_1 = sk_1;
        this.sk_y = sk_y;
        this.sk_th = sk_th;
        this.attributes = attributes;
    }

}
