package cn.edu.buaa.crypto.encryption.AOACE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class AuthenticationCiphertext {
    public String[] Ac;
    public Element E0,E1;
    public Map<String, Element> Es2,Es3;
    public AuthenticationCiphertext(Element E0, Element E1,Map<String, Element> Es2,Map<String, Element> Es3,String[] Ac){
        this.Ac = Ac;
        this.E0 = E0;
        this.E1 = E1;
        this.Es2 = Es2;
        this.Es3 = Es3;
    }
}
