package cn.edu.buaa.crypto.encryption.ETkpabe;

import it.unisa.dia.gas.jpbc.Element;
public class PlainText {
    public boolean flag;
    public Element Plain;
    public PlainText(boolean flag,Element m){
        this.flag = flag;
        this.Plain = m;
    }
}
