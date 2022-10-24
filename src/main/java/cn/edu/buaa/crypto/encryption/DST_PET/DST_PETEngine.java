package cn.edu.buaa.crypto.encryption.DST_PET;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

public class DST_PETEngine {
    private static DST_PETEngine engine;
    public BigInteger n,n_square,g,h;
    private int bitLength;

    public static DST_PETEngine getInstance() {
        if (engine == null) {
            engine = new DST_PETEngine();
        }
        return engine;
    }
    public SecretKeys Setup(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //随机构造两个大素数，详情参见API，BigInteger的构造方法
        BigInteger p = new BigInteger(bitLength / 2, certainty, new Random());
        BigInteger q = new BigInteger(bitLength / 2, certainty, new Random());

        //n=p*q;
        n = p.multiply(q);

        //nsquare=n*n;
        n_square = n.multiply(n);

        BigInteger x1,x2,x;
        while (true){
            x1 = new BigInteger(n.bitLength(), new Random());
            if(x1.compareTo(n_square.divide(new BigInteger("2"))) <= 0 && x1.compareTo(BigInteger.ONE) >= 0) break;
        }
        while (true){
            x2 = new BigInteger(n.bitLength(), new Random());
            if(x2.compareTo(n_square.divide(new BigInteger("2"))) <= 0 && x2.compareTo(BigInteger.ONE) >= 0) break;
        }

        x = x1.add(x2).mod(n_square);

        BigInteger a;
        do{
            a = new BigInteger(n.bitLength(), new Random());
        }while (a.compareTo(n_square) >= 0);
        g = a.modPow(new BigInteger("2").multiply(n),n_square);

        h = g.modPow(x,n_square);

        return new SecretKeys(x1,x2);
    }

//    public CipherText[] Encrypt(BigInteger[] m){
//        CipherText[] ct = new CipherText[m.length];
//        for(int i=0;i<m.length;i++){
//            BigInteger r = new BigInteger(bitLength, new Random());
//            BigInteger T1 = g.modPow(r,n_square);
//            BigInteger T2 = h.modPow(r,n_square).multiply(m[i].multiply(n).add(BigInteger.ONE)).mod(n_square);
//            ct[i] = new CipherText(T1,T2);
//        }
//        return ct;
//    }

    public CipherText En(BigInteger m){
        BigInteger r = new BigInteger(bitLength, new Random());
        BigInteger T1 = g.modPow(r,n_square);
        BigInteger T2 = h.modPow(r,n_square).multiply(m.multiply(n).add(BigInteger.ONE)).mod(n_square);
        return new CipherText(T1,T2);
    }

    public CipherText De1(CipherText ct,BigInteger x){
        BigInteger r = new BigInteger(bitLength, new Random());
        BigInteger T2 = ct.T2.multiply(ct.T1.modPow(x,n_square).modInverse(n_square)).mod(n_square);
        return new CipherText(ct.T1,T2);
    }

    public BigInteger De(CipherText ct,BigInteger x){
        BigInteger u = ct.T2.multiply(ct.T1.modPow(x,n_square).modInverse(n_square)).mod(n_square);
        return u.subtract(BigInteger.ONE).divide(n).mod(n_square);
    }

    public CipherText multiply(CipherText ct1,CipherText ct2){
        return new CipherText(ct1.T1.multiply(ct2.T1).mod(n_square),ct1.T2.multiply(ct2.T2).mod(n_square));
    }

    public CipherText pow(CipherText ct,BigInteger c){
        return new CipherText(ct.T1.modPow(c,n_square),ct.T2.modPow(c,n_square));
    }

    public CipherText Test(CipherText[] ct,BigInteger[] P0,BigInteger[] P1,BigInteger[] C,BigInteger c0){
        CipherText E1 = En(BigInteger.ONE.negate());
        CipherText E0 = En(BigInteger.ZERO);
        CipherText[] tmp = new CipherText[ct.length];
        for(int i=0;i<ct.length;i++){
            CipherText x1 = pow(multiply(ct[i],E1),P0[i].negate());
            CipherText x2 = pow(multiply(ct[i],E0),P1[i]);
            tmp[i] = pow(multiply(x1,x2),C[i]);
        }

        CipherText res = tmp[0];
        for(int i=1;i<ct.length;i++){
            res = multiply(res,tmp[i]);
        }
        return pow(res,c0);
    }
//    public static void main(String[] args) {
//        DST_PETEngine engine = new DST_PETEngine();
//        SecretKeys sks = engine.Setup(32,64);
//        BigInteger sk1 = sks.getX1();
//        BigInteger sk2 = sks.getX2();
//
//        BigInteger m = new BigInteger(32, new Random());
//        System.out.println("m:"+m);
//        CipherText ct = engine.En(m,sk2);
//
//        CipherText ct1 = engine.De1(ct,sk1);
//        System.out.println("m:"+engine.De(ct1,sk2));
//
//    }


}
