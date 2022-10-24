package cn.edu.buaa.crypto.encryption.PPGPT_PET;

import java.math.BigInteger;
import java.util.Random;

public class PPGPTEngine {
    private static PPGPTEngine engine;
    public BigInteger g,n;
    public BigInteger n_square;
    private int bitLength;
    public static PPGPTEngine getInstance(){
        if(engine == null){
            engine = new PPGPTEngine();
        }
        return engine;
    }

    public MasterSecretKey setup(int bitLengthVal, int certainty) {
        bitLength = bitLengthVal;
        //随机构造两个大素数，详情参见API，BigInteger的构造方法
        BigInteger p = new BigInteger(bitLength / 2, certainty, new Random());
        BigInteger q = new BigInteger(bitLength / 2, certainty, new Random());

        //n=p*q;
        this.n = p.multiply(q);

        //nsquare=n*n;
        this.n_square = this.n.multiply(n);
        this.g=new BigInteger("2");

        //求p-1与q-1的乘积除于p-1于q-1的最大公约数
        BigInteger lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                .divide(p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));

        //检测g是某满足要求
        if (g.modPow(lambda, n_square).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
            System.out.println("g的选取不合适!");
            System.exit(1);
        }
        return new MasterSecretKey(lambda);
    }

    public BigInteger En(BigInteger m) {
        BigInteger r = new BigInteger(bitLength, new Random());
        return g.modPow(m, n_square).multiply(r.modPow(n, n_square)).mod(n_square);
    }

    public BigInteger Server_En(BigInteger en_c,BigInteger m){
        //System.out.println("test:"+En(m.negate()).add(en_c).mod(n));
        BigInteger r = new BigInteger(bitLength, new Random());
        BigInteger en_sc = En(m.negate()).multiply(en_c).modPow(r,n_square);
        return en_sc;
    }

    public BigInteger De(BigInteger c,MasterSecretKey msk) {
        BigInteger u = g.modPow(msk.getLambda(), n_square).subtract(BigInteger.ONE).divide(n).modInverse(n);
        return c.modPow(msk.getLambda(), n_square).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
    }
}
