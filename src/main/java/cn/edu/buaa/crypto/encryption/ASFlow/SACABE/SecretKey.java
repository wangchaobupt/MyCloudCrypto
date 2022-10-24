package cn.edu.buaa.crypto.encryption.ASFlow.SACABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Map;

public class SecretKey {
    ArrayList<Element> sk0,sk_1;
    Map<String, ArrayList<Element>> sk_y;

    public SecretKey(ArrayList<Element> sk0, ArrayList<Element> sk_1, Map<String, ArrayList<Element>> sk_y) {
        this.sk0 = sk0;
        this.sk_1 = sk_1;
        this.sk_y = sk_y;
    }
}
