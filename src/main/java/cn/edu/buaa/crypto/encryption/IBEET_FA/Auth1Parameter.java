package cn.edu.buaa.crypto.encryption.IBEET_FA;

import cn.edu.buaa.crypto.encryption.GT.ELGamal;
import it.unisa.dia.gas.jpbc.Element;
public class Auth1Parameter {
    private Element td;
    public Auth1Parameter(Element td){
        this.td = td;
    }

    public Element getTd() {
        return td;
    }

    public int getlen(){
        return td.toBytes().length;
    }
}
