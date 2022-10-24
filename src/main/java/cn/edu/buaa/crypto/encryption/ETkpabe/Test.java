package cn.edu.buaa.crypto.encryption.ETkpabe;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.util.Arrays;

public class Test {
    public static void main(String[] args) {

        String str = "1 2 3 and";
        System.out.println(str.length());
        System.out.println(str.getBytes().length);
/*
        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        Element m = pairing.getG1().newRandomElement().getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        System.out.println("r:"+r);

        byte[] mbytes = m.toBytes();
        byte[] rbytes = r.toBytes();
        System.out.println("mlen:"+mbytes.length);
        System.out.println("rlen:"+rbytes.length);
        byte[] mr = new byte[mbytes.length + rbytes.length];
        System.arraycopy(mbytes,0,mr,0,mbytes.length);
        System.arraycopy(rbytes,0,mr,mbytes.length,rbytes.length);
        System.out.println("mr:"+Arrays.toString(mr));

        Element x = pairing.getG1().newRandomElement().getImmutable();
        byte[] xbytes = x.toBytes();
        byte[] c = PairingUtils.Xor(mr,xbytes);
        System.out.println("c:"+Arrays.toString(c));

        byte[] c1 = PairingUtils.Xor(c,xbytes);
        System.out.println("c1:"+Arrays.toString(c1));

 */



//        System.out.println("mr:"+ Arrays.toString(mr));
//
//        Element mr1 = pairing.getGT().newElementFromBytes(mr);
//        System.out.println("mr1:"+mr1);
//
//        byte[] res = mr1.toBytes();
//        System.out.println("res:"+Arrays.toString(res));
//        System.out.println("len:"+res.length);

//        Element x = pairing.getG1().newRandomElement().getImmutable();
//        byte[] mxbytes = m.mul(x).getImmutable().toBytes();
//        byte[] mr = new byte[mbytes.length + mxbytes.length];
//        System.arraycopy(mxbytes,0,mr,0,mxbytes.length);
//        System.arraycopy(rbytes,0,mr,mxbytes.length,rbytes.length);
//
//        System.out.println("mbyte:"+ Arrays.toString(mbytes));
//        System.out.println("rbyte:"+ Arrays.toString(rbytes));
//        System.out.println("mxbytes:"+Arrays.toString(mxbytes));
//        System.out.println("mr:"+Arrays.toString(mr));
//
//        byte[] res1 =  Arrays.copyOfRange(mr, 0, 64);
//        byte[] res2 = Arrays.copyOfRange(mr,64,mr.length);
//        System.out.println("res1:"+Arrays.toString(res1));
//        System.out.println("res2:"+Arrays.toString(res2));

//        byte[] R = new byte[10];
//        int size=0;
//        for(int i=0;i<res2.length;i++){
//            if(res2[i]!=0){
//                R[size++] = res2[i];
//            }
//            if(size==10) break;
//        }
//        System.out.println("R:"+Arrays.toString(R));
        //System.out.println("element:"+pairing.getZr().newElementFromBytes(res2));

    }
}
