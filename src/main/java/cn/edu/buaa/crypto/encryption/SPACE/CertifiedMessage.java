package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import it.unisa.dia.gas.jpbc.Element;
public class CertifiedMessage {
    public Element msg;
    public Element[] O;
    public String[] W;
    public SignParameter sign_w;
    public CertifiedMessage(Element msg,Element[] O,String[] W,SignParameter sign_w){
        this.msg = msg;
        this.O = O;
        this.sign_w = sign_w;
        this.W = W;
    }
}
