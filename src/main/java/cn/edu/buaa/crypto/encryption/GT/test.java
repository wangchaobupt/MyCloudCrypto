package cn.edu.buaa.crypto.encryption.GT;

import org.bouncycastle.jcajce.provider.asymmetric.ElGamal;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class test {
//    public static void main(String[] args) {
//        BigDecimal num = new BigDecimal("12341239418");
//        long time;
//        time = System.nanoTime();
//
//        int n = 365;
//        int scale = 8;
//        BigDecimal root = bigRoot(num, n, scale, BigDecimal.ROUND_HALF_UP);
//        time = System.nanoTime() - time;
//        System.out.println("根：" + root);
//        System.out.println("反算：" + root.pow(n));
//        System.out.println("原值：" + num);
//        System.out.println("耗时/ms：" + time / 1000000);
//    }
//
//
//    /*
//     * BigDecimal开n次方根。
//     * 转载于：https://www.xuebuyuan.com/1863340.html
//     * @param number 被开方数
//     * @param n n次方根
//     * @param scale 精度
//     * @param roundingMode 舍入规则
//     * @return 结果
//     */
//    public static BigDecimal bigRoot(BigDecimal number, int n, int scale, int roundingMode) {
//        boolean negate = false;
//        if (n < 0)
//            throw new ArithmeticException();
//        if (number.compareTo(BigDecimal.ZERO) < 0) {
//            if (n % 2 == 0)
//                throw new ArithmeticException();
//            else {
//                number = number.negate();
//                negate = true;
//            }
//        }
//
//        BigDecimal root;
//
//        if (n == 0)
//            root = BigDecimal.ONE;
//        else if (n == 1)
//            root = number;
//        else {
//            final BigInteger N = BigInteger.valueOf(n);
//            final BigInteger N2 = BigInteger.TEN.pow(n);
//            final BigInteger N3 = BigInteger.TEN.pow(n - 1);
//            final BigInteger NINE = BigInteger.valueOf(9);
//
//            BigInteger[] C = new BigInteger[n + 1];
//            for (int i = 0; i <= n; i++) {
//                C[i] = combination(n, i);
//            }
//
//            BigInteger integer = number.toBigInteger();
//            String strInt = integer.toString();
//            int lenInt = strInt.length();
//            for (int i = lenInt % n; i < n && i > 0; i++)
//                strInt = "0" + strInt;
//            lenInt = (lenInt + n - 1) / n * n;
//            BigDecimal fraction = number.subtract(number.setScale(0, BigDecimal.ROUND_DOWN));
//            int lenFrac = (fraction.scale() + n - 1) / n * n;
//            fraction = fraction.movePointRight(lenFrac);
//            String strFrac = fraction.toPlainString();
//            for (int i = strFrac.length(); i < lenFrac; i++)
//                strFrac = "0" + strFrac;
//
//            BigInteger res = BigInteger.ZERO;
//            BigInteger rem = BigInteger.ZERO;
//            for (int i = 0; i < lenInt / n; i++) {
//                rem = rem.multiply(N2);
//
//                BigInteger temp = new BigInteger(strInt.substring(i * n, i * n + n));
//                rem = rem.add(temp);
//
//                BigInteger j;
//                if (res.compareTo(BigInteger.ZERO) != 0)
//                    j = rem.divide(res.pow(n - 1).multiply(N).multiply(N3));
//                else
//                    j = NINE;
//                BigInteger test = BigInteger.ZERO;
//                temp = res.multiply(BigInteger.TEN);
//                while (j.compareTo(BigInteger.ZERO) >= 0) {
//                    //test = res.multiply(BigInteger.TEN);
//                    //test = ((test.add(j)).pow(n)).subtract(test.pow(n));
//                    test = BigInteger.ZERO;
//                    if (j.compareTo(BigInteger.ZERO) > 0)
//                        for (int k = 1; k <= n; k++)
//                            test = test.add(j.pow(k).multiply(C[k]).multiply(temp.pow(n - k)));
//                    if (test.compareTo(rem) <= 0)
//                        break;
//                    j = j.subtract(BigInteger.ONE);
//                }
//
//                rem = rem.subtract(test);
//                res = res.multiply(BigInteger.TEN);
//                res = res.add(j);
//            }
//            for (int i = 0; i <= scale; i++) {
//                rem = rem.multiply(N2);
//
//                if (i < lenFrac / n) {
//                    BigInteger temp = new BigInteger(strFrac.substring(i * n, i * n + n));
//                    rem = rem.add(temp);
//                }
//
//                BigInteger j;
//                if (res.compareTo(BigInteger.ZERO) != 0) {
//                    j = rem.divide(res.pow(n - 1).multiply(N).multiply(N3));
//                } else
//                    j = NINE;
//                BigInteger test = BigInteger.ZERO;
//                BigInteger temp = res.multiply(BigInteger.TEN);
//                while (j.compareTo(BigInteger.ZERO) >= 0) {
//                    //test = res.multiply(BigInteger.TEN);
//                    //test = ((test.add(j)).pow(n)).subtract(test.pow(n));
//                    test = BigInteger.ZERO;
//                    if (j.compareTo(BigInteger.ZERO) > 0)
//                        for (int k = 1; k <= n; k++)
//                            test = test.add(j.pow(k).multiply(C[k]).multiply(temp.pow(n - k)));
//                    if (test.compareTo(rem) <= 0)
//                        break;
//                    j = j.subtract(BigInteger.ONE);
//                }
//
//                rem = rem.subtract(test);
//                res = res.multiply(BigInteger.TEN);
//                res = res.add(j);
//            }
//            root = new BigDecimal(res).movePointLeft(scale + 1);
//            if (negate)
//                root = root.negate();
//        }
//        return root.setScale(scale, roundingMode);
//    }
//
//    public static BigInteger combination(int n, int k) {
//        if (k > n || n < 0 || k < 0)
//            return BigInteger.ZERO;
//        if (k > n / 2)
//            return combination(n, n - k);
//        BigInteger N1 = BigInteger.ONE;
//        BigInteger N2 = BigInteger.ONE;
//        BigInteger N = BigInteger.valueOf(n);
//        BigInteger K = BigInteger.valueOf(k);
//        for (int i = 0; i < k; i++) {
//            N1 = N1.multiply(N);
//            N2 = N2.multiply(K);
//            N = N.subtract(BigInteger.ONE);
//            K = K.subtract(BigInteger.ONE);
//        }
//        return N1.divide(N2);
//    }

    //num是被开方数，n是开方次数,precision设置保留几位小数
        public static String  rootN_Decimal(String num,int n,int precision)
        {

            BigDecimal x=new BigDecimal(new BigInteger(num).divide(new BigInteger(n+"")));
            BigDecimal x0=BigDecimal.ZERO;

            BigDecimal e=new BigDecimal("0.1");
            for(int i=1;i<precision;++i)
                e=e.divide(BigDecimal.TEN,i+1,BigDecimal.ROUND_HALF_EVEN);

            BigDecimal K=new BigDecimal(num);
            BigDecimal m=new BigDecimal(n);

            long i=0;
            while(x.subtract(x0).abs().compareTo(e)>0)
            {
                x0=x;
                x=x.add(K.subtract(x.pow(n)).divide(m.multiply(x.pow(n-1)),precision,BigDecimal.ROUND_HALF_EVEN));
                ++i;
            }
            return x+" "+i;
        }

        public static void main(String[] args)
        {
            BigInteger b=new BigInteger("1234567891548687");
//            BigInteger a = new BigInteger("12343421552");
//            b=b.pow(10);

            System.out.println(rootN_Decimal(b.toString(), 4564, 2));
        }


}
/*
　　p=2579
　　α=2
　　d=765
　　M=1299
　　k=853
 */