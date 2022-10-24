package cn.edu.buaa.crypto.encryption.IBEET_FA;

import it.unisa.dia.gas.jpbc.Element;
public class Auth4Parameter {
    private byte[] td2;
    private Element td1;
    public Auth4Parameter(byte[] td2,Element td1){
        this.td1 = td1;
        this.td2 = td2;
    }

    public Element getTd1() {
        return td1;
    }

    public byte[] getTd2() {
        return td2;
    }

    public int getlen(){
        return td2.length + td1.toBytes().length;
    }
}
