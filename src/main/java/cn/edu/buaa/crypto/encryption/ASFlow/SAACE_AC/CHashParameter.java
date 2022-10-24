package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_AC;

import it.unisa.dia.gas.jpbc.Element;

public class CHashParameter {
    public byte[][] Cbytes;
    public CHashParameter(Element C, Element ct01, Element ct02, Element Q, Element P, Element R,
                          Element A1, Element A2,Element B, Element E1, Element E2, Element E3,
                          Element E4, Element E5, Element E6){
        Cbytes = new byte[15][];
        Cbytes[0] = C.toBytes();
        Cbytes[1] = ct01.toBytes();
        Cbytes[2] = Q.toBytes();
        Cbytes[3] = P.toBytes();
        Cbytes[4] = R.toBytes();
        Cbytes[5] = A1.toBytes();
        Cbytes[6] = A2.toBytes();
        Cbytes[7] = B.toBytes();
        Cbytes[8] = E1.toBytes();
        Cbytes[9] = E2.toBytes();
        Cbytes[10] = E3.toBytes();
        Cbytes[11] = E4.toBytes();
        Cbytes[12] = E5.toBytes();
        Cbytes[13] = E6.toBytes();
        Cbytes[14] = ct02.toBytes();
    }

    public int getlen(){
        int len = Cbytes[0].length;
        for(int i=1;i<Cbytes.length;i++){
            len+=Cbytes[i].length;
        }
        return len;
    }

    public byte[] getCbytes(){
        int len = getlen();

        byte[] res = new byte[len];
        int strat = 0;
        for(int i=0;i<15;i++){
            System.arraycopy(Cbytes[i],0,res,strat,Cbytes[i].length);
            strat+=Cbytes[i].length;
        }
        return res;
    }
}
