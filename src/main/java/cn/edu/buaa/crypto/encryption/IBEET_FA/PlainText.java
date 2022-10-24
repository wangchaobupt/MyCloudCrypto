package cn.edu.buaa.crypto.encryption.IBEET_FA;

import it.unisa.dia.gas.jpbc.Element;
public class PlainText {
    public boolean flag;
    public Element plain;
    public PlainText(boolean flag,Element m){
        this.flag = flag;
        this.plain = m;
    }
}
