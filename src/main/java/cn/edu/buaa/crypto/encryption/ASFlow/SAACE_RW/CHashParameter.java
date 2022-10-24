package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;
import it.unisa.dia.gas.jpbc.Element;
public class CHashParameter {
    public byte[][] Cbytes;
    public CHashParameter(Element C,Element C0,Element Q,Element P,Element R,
                          Element A,Element B,Element E1,Element E2,Element E3,
                          Element E4,Element E5,Element E6){
        Cbytes = new byte[13][];
        Cbytes[0] = C.toBytes();
        Cbytes[1] = C0.toBytes();
        Cbytes[2] = Q.toBytes();
        Cbytes[3] = P.toBytes();
        Cbytes[4] = R.toBytes();
        Cbytes[5] = A.toBytes();
        Cbytes[6] = B.toBytes();
        Cbytes[7] = E1.toBytes();
        Cbytes[8] = E2.toBytes();
        Cbytes[9] = E3.toBytes();
        Cbytes[10] = E4.toBytes();
        Cbytes[11] = E5.toBytes();
        Cbytes[12] = E6.toBytes();
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
        for(int i=0;i<13;i++){
            System.arraycopy(Cbytes[i],0,res,strat,Cbytes[i].length);
            strat+=Cbytes[i].length;
        }
        return res;
    }
}
