package cn.edu.buaa.crypto.encryption.P2GT_plus.GPT;

import it.unisa.dia.gas.jpbc.Element;

public class Trapdoor {
    private Element u,g,Ka,Ka1,Kb,Kb1;
    public Trapdoor(Element u, Element g, Element ka, Element ka1, Element kb, Element kb1){
        this.g = g;
        this.Ka = ka;
        this.Ka1 = ka1;
        this.Kb = kb;
        this.Kb1 = kb1;
        this.u = u;
    }

    public Element getU() {
        return u;
    }

    public Element getG() {
        return g;
    }

    public Element getKa() {
        return Ka;
    }

    public Element getKa1() {
        return Ka1;
    }

    public Element getKb() {
        return Kb;
    }

    public Element getKb1() {
        return Kb1;
    }

    public int getlen(){
        return u.toBytes().length + g.toBytes().length + Ka.toBytes().length + Ka1.toBytes().length + Kb.toBytes().length + Kb1.toBytes().length;
    }
}
