package cn.edu.buaa.crypto.encryption.DST_PET;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Random;

public class Paillier {
    private BigInteger p, q;
    public BigInteger n,n_square,g,h,x;
    private int bitLength;

    public Paillier(int bitLengthVal, int certainty) {
        Key(bitLengthVal, certainty);
    }
    public Paillier() {
        Key(32, 64);
    }
    public void Key(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //随机构造两个大素数，详情参见API，BigInteger的构造方法
        p = new BigInteger(bitLength / 2, certainty, new Random());
        q = new BigInteger(bitLength / 2, certainty, new Random());

        //n=p*q;
        n = p.multiply(q);

        //nsquare=n*n;
        n_square = n.multiply(n);

        while (true){
            x = new BigInteger(n.bitLength(), new Random());
            if(x.compareTo(n_square.divide(new BigInteger("2"))) <= 0 && x.compareTo(BigInteger.ONE) >= 0) break;
        }

        BigInteger a;
        do{
            a = new BigInteger(n.bitLength(), new Random());
        }while (a.compareTo(n_square) >= 0);
        g = a.modPow(new BigInteger("2").multiply(n),n_square);

        h = g.modPow(x,n_square);
    }

    public CipherText En(BigInteger m){
        BigInteger r = new BigInteger(bitLength, new Random());
        BigInteger T1 = g.modPow(r,n_square);
        BigInteger T2 = h.modPow(r,n_square).multiply(m.multiply(n).add(BigInteger.ONE)).mod(n_square);
        return new CipherText(T1,T2);
    }

    public BigInteger De(CipherText ct){
        BigInteger u = ct.T2.multiply(ct.T1.modPow(x,n_square).modInverse(n_square)).mod(n_square);
        return u.subtract(BigInteger.ONE).divide(n).mod(n_square);
    }

    public CipherText multiply(CipherText ct1,CipherText ct2){
        return new CipherText(ct1.T1.multiply(ct2.T1).mod(n_square),ct1.T2.multiply(ct2.T2).mod(n_square));
    }

    public CipherText pow(CipherText ct,BigInteger c){
        return new CipherText(ct.T1.modPow(c,n_square),ct.T2.modPow(c,n_square));
    }

    public BigInteger Sqrt(BigInteger xx)
    {
        BigDecimal x=new BigDecimal(xx);
        BigDecimal n1=BigDecimal.ONE;
        BigDecimal ans=BigDecimal.ZERO;
        while((n1.multiply(n1).subtract(x)).abs().compareTo(BigDecimal.valueOf(0.001))==1)
        {
            BigDecimal s1=x.divide(n1,2000,BigDecimal.ROUND_HALF_UP);
            BigDecimal s2=n1.add(s1);
            n1=s2.divide(BigDecimal.valueOf(2),2000,BigDecimal.ROUND_HALF_UP);

        }
        ans=n1;
        BigInteger rt =new BigInteger(ans.toString().split("\\.")[0]);
        return rt;
    }

    public static void main(String[] args) {

        BigInteger m2 = new BigInteger(32, new Random());
        BigInteger n = new BigInteger("400");
        Paillier paillier = new Paillier();
        BigInteger m = paillier.Sqrt(m2);
        System.out.println(m);

//        Paillier paillier = new Paillier();
//        BigInteger m1 = new BigInteger("20");
//        BigInteger m2 = new BigInteger("10");
//        System.out.println("m1:"+m1);
//        System.out.println("m2:"+m2);
//        CipherText em1 = paillier.En(m1);
//        CipherText em2 = paillier.En(m2);
//        System.out.println("m1:"+paillier.De(em1));
//        System.out.println("m2:"+paillier.De(em2));
//
//        BigInteger sum_m1m2 = m1.add(m2.negate()).mod(paillier.n_square);
//        CipherText em12 = paillier.En(sum_m1m2);
//        System.out.println("sum:"+paillier.De(em12));
//
//        em2 = paillier.En(m2.negate());
//        CipherText em1em2 = paillier.multiply(em1,em2);
//        System.out.println("em_sum:"+paillier.De(em1em2));

//        BigInteger mul_m1m2 = m1.multiply(m2).mod(paillier.n_square);
//        CipherText mul12 = paillier.En(mul_m1m2);
//        System.out.println("mul:"+paillier.De(mul12));
//
//        CipherText mul_em12 = paillier.pow(em1,m2);
//        System.out.println("em_mul:"+paillier.De(mul_em12));
    }
}
