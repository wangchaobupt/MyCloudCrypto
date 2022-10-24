package cn.edu.buaa.crypto.encryption.GT;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class PSI_CAEngine {
    private static PSI_CAEngine engine;
    private BigInteger p,q,g;
    public void setup(int n){
        Random r = new Random();
        while (true) {
            q = BigInteger.probablePrime(n, r);
            if (q.bitLength() != n)
                continue;
            if (q.isProbablePrime(10)) // 如果q为素数则再进一步计算生成元
            {
                p = q.multiply(new BigInteger("2")).add(BigInteger.ONE);
                if (p.isProbablePrime(10)) // 如果P为素数则OK~，否则继续
                    break;
            }
        }
        g = BigInteger.valueOf(2);
        while (true) {
            if (g.gcd(q).equals(BigInteger.ONE)) {
                break;
            }
            g = g.add(BigInteger.ONE);
        }
    }

//    public List<BigInteger> S_offline(List<BigInteger> s){
//        Collections.shuffle(s);
//        BigInteger Rs = new BigInteger(q.bitLength()-1,new Random());
//        BigInteger Rs1 = new BigInteger(q.bitLength()-1,new Random());
//        BigInteger
//    }

    public String shaEncode(String inStr) throws Exception {
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }

        byte[] byteArray = inStr.getBytes("UTF-8");
        byte[] md5Bytes = sha.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }


}
