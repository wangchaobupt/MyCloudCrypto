package cn.edu.buaa.crypto.encryption.ASFlow.SACABE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;

public class MasterSecretKey {
    ArrayList<Element> a,b,g_d;

    public MasterSecretKey(ArrayList<Element> a, ArrayList<Element> b, ArrayList<Element> g_d) {
        this.a = a;
        this.b = b;
        this.g_d = g_d;
    }
}
