package cn.edu.buaa.crypto.encryption.SPACE;

import it.unisa.dia.gas.jpbc.Element;

public class CHashParameter {
    public byte[][] Cbytes;
    public CHashParameter(Element C,Element C0,Element Q,Element P,Element P1,
                          Element X1,Element X2,Element E1,Element E2,Element E3){
        Cbytes = new byte[10][];
        Cbytes[0] = C.toBytes();
        Cbytes[1] = C0.toBytes();
        Cbytes[2] = Q.toBytes();
        Cbytes[3] = P.toBytes();
        Cbytes[4] = P1.toBytes();
        Cbytes[5] = X1.toBytes();
        Cbytes[6] = X2.toBytes();
        Cbytes[7] = E1.toBytes();
        Cbytes[8] = E2.toBytes();
        Cbytes[9] = E3.toBytes();
    }

    public int getlen(){
        int len = Cbytes[0].length;
        for(int i=1;i<Cbytes.length;i++){
            len += Cbytes[i].length;
        }
        return len;
    }

    public byte[] getCbytes(){
        int len = getlen();
        byte[] res = new byte[len];
        int start = 0;
        for(int i=0;i<10;i++){
            System.arraycopy(Cbytes[i],0,res,start,Cbytes[i].length);
            start+=Cbytes[i].length;
        }
        return res;
    }
}
