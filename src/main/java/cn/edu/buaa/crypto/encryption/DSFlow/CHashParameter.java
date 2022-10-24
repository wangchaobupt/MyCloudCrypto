package cn.edu.buaa.crypto.encryption.DSFlow;

import it.unisa.dia.gas.jpbc.Element;

public class CHashParameter {
    public byte[][] Cbytes;
    public CHashParameter(Element C, Element C0, Element Q, Element P, Element X1, Element X2, Element D1, Element D2, Element D3,Element E3, Element E4){
        Cbytes = new byte[11][];
        Cbytes[0] = C.toBytes();
        Cbytes[1] = C0.toBytes();
        Cbytes[2] = Q.toBytes();
        Cbytes[3] = P.toBytes();
        Cbytes[4] = X1.toBytes();
        Cbytes[5] = X2.toBytes();
        Cbytes[6] = D1.toBytes();
        Cbytes[7] = D2.toBytes();
        Cbytes[8] = D3.toBytes();
        Cbytes[9] = E3.toBytes();
        Cbytes[10] = E4.toBytes();
    }

    public int getlen(){
        int len = Cbytes[0].length;
        for(int i=1;i<Cbytes.length;i++){
            len+=Cbytes[i].length;
        }
        return len;
    }

}
