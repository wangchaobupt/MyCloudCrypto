package cn.edu.buaa.crypto.encryption.GT;


import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class ELGamal {
    static BigInteger p, g; // 大素数和本原元
    static BigInteger C, C1;// 密文

    public static double entropy(String mess) {
        ArrayList<Node> jieguo = new ArrayList<Node>();
        jieguo.clear();
        double num = mess.length();
        for (int i = 0; i < num; i++) {
            boolean flag_exit = true;
            for (int j = 0; j < jieguo.size(); j++) {
                if (jieguo.get(j).getalpha() == mess.charAt(i)) {
                    flag_exit = false;
                    jieguo.get(j).setp(jieguo.get(j).getp() + 1 / num);
                }
            }
            if (flag_exit)
                jieguo.add(new Node(1 / num, mess.charAt(i)));
        }
        /** 计算熵 */
        double entropy = 0;
        for (int i = 0; i < jieguo.size(); i++) {
            double p1 = jieguo.get(i).getp();
            entropy += (-p1 * (Math.log(p1) / Math.log(2)));
        }
        return entropy;
    }

    /**
     * 取一个大的随机素数P,和P的生成元a
     */
    public static void getRandomP(int alpha) {
        Random r = new Random();
        BigInteger q = null;
        while (true) {
            q = BigInteger.probablePrime(alpha, r);
            if (q.bitLength() != alpha)
                continue;
            if (q.isProbablePrime(10)) // 如果q为素数则再进一步计算生成元
            {
                p = q.multiply(new BigInteger("2")).add(BigInteger.ONE);
                if (p.isProbablePrime(10)) // 如果P为素数则OK~，否则继续
                    break;
            }
        }
        while (true) {
            g = BigInteger.probablePrime(p.bitLength() - 1, r);
            if (!g.modPow(BigInteger.ONE, p).equals(BigInteger.ONE)
                    && !g.modPow(q, p).equals(BigInteger.ONE)) {
                break;
            }
        }
    }

    /**
     * 取随机数a
     */
    public static BigInteger getRandoma(BigInteger p) {
        BigInteger a;
        Random r = new Random();
        a = new BigInteger(p.bitLength() - 1, r);
        return a;
    }

    /**
     * 计算密钥的值
     */
    public static BigInteger calculatey(BigInteger x, BigInteger g, BigInteger p) {
        BigInteger y;
        y = g.modPow(x, p);
        return y;
    }

    /**
     * 加密
     */
    public static void encrypt(String m, BigInteger y, BigInteger p,
                               BigInteger g) {
        BigInteger message = new BigInteger(m.getBytes());// 把字串转成一个BigInteger对象
        Random r = new Random();
        BigInteger k;
        while (true) {
            k = new BigInteger(p.bitLength() - 1, r);// 产生一0<=k<p-1的随机数
            if (k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {// 如果随机数与p-1互质
                // 则选取成功,返回随机数k
                break;
            }
        }
        // 计算密文C,C1
        C = g.modPow(k, p);
        C1 = message.multiply(y.modPow(k, p)).mod(p);
        // 保存密文到对象中

    }

    /**
     * 解密
     */
    public static String decrypt(BigInteger C, BigInteger C1, BigInteger a,
                                 BigInteger p) {
        BigInteger scy = C1.multiply(C.modPow(a.negate(), p)).mod(p);
        String str = new String(scy.toByteArray());// 把返回的结果还原成一个字串
        return str;
    }

    public static void main(String[] args) {
        BigInteger y, x; // 随机数 P,g是P的生成元，公钥<y,g,p>，私钥<x,g,p> 0<a<p
        System.out.println("请输入明文:");

        while (true) {
            Scanner input = new Scanner(System.in);
            String str = input.nextLine();
            System.out.println("len1:"+str.getBytes().length);
            System.out.println("len:"+new BigInteger(str.getBytes()).bitLength());
            //ELGamal.getRandomP(new BigInteger(str.getBytes()).bitLength());// 取得随机数P,和P的生成元g
            ELGamal.getRandomP(100);
            x = ELGamal.getRandoma(p);
            y = ELGamal.calculatey(x, g, p);
            System.out.println("计算机随机生成的素数P:" + p);
            System.out.println("求得其生成元:" + g);
            System.out.println("私钥<x,g,p>为: (" + x + "," + g + "," + p + ")");
            System.out.println("公钥<y,g,p>为:" + "(" + y + "," + g + "," + p
                    + ")");
            x = ELGamal.getRandoma(p);
            y = ELGamal.calculatey(x, g, p);
            ELGamal.encrypt(str, y, p, g);
            System.out
                    .println("计算得到的明文熵：" + entropy(str.getBytes().toString()));
            System.out.println("加密后的密文为:" + C + "," + C1);
            System.out.println("计算得到的密文熵："
                    + entropy(C.toString().concat(C1.toString())));
            String designm = ELGamal.decrypt(C, C1, x, p);
            System.out.println("解密得到明文为:" + designm);
        }
    }
}
