package cn.edu.buaa.crypto.encryption.PMT3;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class PMT3Engine {
    private static PMT3Engine engine;
    private BigInteger n,e,d,max,g;
    private BigInteger Rs;
    private BigInteger[] Rc;

    public static PMT3Engine getInstance() {
        if (engine == null) {
            engine = new PMT3Engine();
        }
        return engine;
    }
    public void initKey(){
        try {
            //rsa工厂
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //长度
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            this.n = rsaPublicKey.getModulus();
            this.e = rsaPublicKey.getPublicExponent();
            this.max = getSqrt(this.n).divide(BigInteger.valueOf(2));

            System.out.println("n:"+this.n);
            System.out.println("e:"+this.e);
            //私钥
            RSAPrivateKey rsaPrivateKey=(RSAPrivateKey) keyPair.getPrivate();
            this.d = rsaPrivateKey.getPrivateExponent();

            System.out.println("d:"+this.d);

            this.g = BigInteger.valueOf(2);
            while (true) {
                if (this.g.gcd(this.n).equals(BigInteger.ONE)) {
                    break;
                }
                this.g = this.g.add(BigInteger.ONE);
            }
            System.out.println("g:"+this.g);
            System.out.println("max:"+this.max);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public List<BigInteger> getSign(List<BigInteger> C){
        List<BigInteger> sign = new ArrayList<BigInteger>();
        for(int i=0;i<C.size();i++){
            sign.add(BigInteger.valueOf(C.get(i).hashCode()).modPow(this.d,this.n));
        }

        return sign;
    }

    private static BigInteger getSqrt(BigInteger num) {
        String s = num.toString();
        int mlen = s.length();    //被开方数的长度
        int len;    //开方后的长度
        BigInteger beSqrtNum = new BigInteger(s);//被开方数
        BigInteger sqrtOfNum;    //存储开方后的数
        BigInteger sqrtOfNumMul;    //开方数的平方
        String sString;//存储sArray转化后的字符串
        if (mlen % 2 == 0) len = mlen / 2;
        else len = mlen / 2 + 1;
        char[] sArray = new char[len];
        Arrays.fill(sArray, '0');//开方数初始化为0
        for (int pos = 0; pos < len; pos++) {
            //从最高开始遍历数组，
            //每一位都转化为开方数平方后刚好不大于被开方数的程度
            for (char ch = '1'; ch <= '9'; ch++) {
                sArray[pos] = ch;
                sString = String.valueOf(sArray);
                sqrtOfNum = new BigInteger(sString);
                sqrtOfNumMul = sqrtOfNum.multiply(sqrtOfNum);
                if (sqrtOfNumMul.compareTo(beSqrtNum) == 1) {
                    sArray[pos] -= 1;
                    break;
                }
            }
        }
        return new BigInteger(String.valueOf(sArray));
    }

    public OfflineParameter S_offline(List<BigInteger> s){
        Collections.shuffle(s);
        do{
            this.Rs = new BigInteger(max.bitLength(),new Random());
        }while (Rs.compareTo(max)>0);
        List<BigInteger> ks = new ArrayList<BigInteger>();
        List<BigInteger> ts = new ArrayList<BigInteger>();
        for(int i=0;i<s.size();i++){
            ks.add(BigInteger.valueOf(s.get(i).hashCode()).modPow(this.Rs.multiply(BigInteger.valueOf(2)),this.n));
        }

        for(int i=0;i<s.size();i++){
            ts.add(BigInteger.valueOf(ks.get(i).hashCode()));
        }
        return new OfflineParameter(ts);
    }

    public C_OnlineParameter C_Online(List<BigInteger> sign){
        Rc = new BigInteger[sign.size()];
        for(int i=0;i<sign.size();i++){
            do{
                this.Rc[i] = new BigInteger(max.bitLength(),new Random());
            }while (this.Rc[i].compareTo(max)>0);
        }

        List<BigInteger> a = new ArrayList<BigInteger>();
        for(int i=0;i<sign.size();i++){
            a.add(sign.get(i).multiply(this.g.modPow(this.Rc[i],this.n)).remainder(this.n));
        }
        return new C_OnlineParameter(a);
    }

    public S_OnlineParameter S_Onlien(C_OnlineParameter C){
        BigInteger Y = this.g.modPow(BigInteger.valueOf(2).multiply(this.e).multiply(this.Rs),this.n);
        List<BigInteger> a1 = new ArrayList<BigInteger>();
        List<BigInteger> a = C.getA();

        for(int i=0;i<a.size();i++){
            a1.add(a.get(i).modPow(BigInteger.valueOf(2).multiply(this.e).multiply(this.Rs),this.n));
        }
        return new S_OnlineParameter(Y,a1);
    }
/*
    public List<BigInteger> Test(S_OnlineParameter S,OfflineParameter TS,List<BigInteger> c,List<BigInteger> sign){
        List<BigInteger> a = S.getA();
        List<BigInteger> ts = TS.getTs();
        List<BigInteger> res = new ArrayList<BigInteger>();
        for(int i=0;i<a.size();i++){
            BigInteger tc = BigInteger.valueOf(a.get(i).multiply(S.getY().modPow(this.Rc[i].negate(),this.n)).remainder(this.n).hashCode());
            for(int j=0;j<ts.size();j++){
                if(ts.get(j).equals(tc)){
                    res.add(c.get(i));
                    ts.remove(j);
                    break;
                }
            }
        }
        return res;
    }

 */
    public List<BigInteger> Test(S_OnlineParameter S){
        List<BigInteger> a = S.getA();
        List<BigInteger> tc = new ArrayList<BigInteger>();
        for(int i=0;i<a.size();i++){
            tc.add( BigInteger.valueOf(a.get(i).multiply(S.getY().modPow(this.Rc[i].negate(),this.n)).remainder(this.n).hashCode()));
        }
        return tc;
    }
}
