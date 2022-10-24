package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;

public class IntermediateCiphertext {
    public Element s,key,C0;
    public Element[] delta,xi,x,Cs1,Cs2,Cs3;
    public IntermediateCiphertext(Element s,Element key,Element C0,Element[] delta,Element[] xi,Element[] x,Element[] Cs1,Element[] Cs2,Element[] Cs3){
        this.s = s;
        this.key = key;
        this.C0 = C0;
        this.x = x;
        this.delta = delta;
        this.xi = xi;
        this.Cs1 = Cs1;
        this.Cs2 = Cs2;
        this.Cs3 = Cs3;
    }
}
