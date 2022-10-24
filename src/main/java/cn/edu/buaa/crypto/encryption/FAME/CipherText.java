package cn.edu.buaa.crypto.encryption.FAME;

import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.Map;

public class CipherText {
    String accessPolicy;
    ArrayList<Element> ct0;
    Map<String, ArrayList<Element>> ct;
    Element ct1;
}
