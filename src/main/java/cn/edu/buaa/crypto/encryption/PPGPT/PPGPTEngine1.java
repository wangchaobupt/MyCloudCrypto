package cn.edu.buaa.crypto.encryption.PPGPT;

public class PPGPTEngine1 {
}
/*
package cn.edu.buaa.crypto.encryption.PPGPT;

import cn.edu.buaa.crypto.encryption.P2GT_plus.PublicKey;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

public class PPGPTEngine {
    private static PPGPTEngine engine;
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

    public OfflineParameter S_offline(List<BigInteger> s){
        Collections.shuffle(s);
        System.out.println("s1:");
        for(int i=0;i<s.size();i++) System.out.println(s.get(i));
        BigInteger Rs = new BigInteger(q.bitLength()-1,new Random());
        BigInteger Rs1 = new BigInteger(q.bitLength()-1,new Random());
        BigInteger Y = g.modPow(Rs,p);
        List<BigInteger> list = new ArrayList<BigInteger>();
        for(int i=0;i<s.size();i++){
            list.add(BigInteger.valueOf(s.get(i).hashCode()).modPow(Rs1,p));
        }
        System.out.println("ks:");
        for(int i=0;i<list.size();i++) System.out.println(list.get(i));
        return new OfflineParameter(Y,list,Rs,Rs1);
    }

    public OfflineParameter C_offline(List<BigInteger> c){
        BigInteger Rc = new BigInteger(q.bitLength()-1,new Random());
        BigInteger Rc1 = new BigInteger(q.bitLength()-1,new Random());
        BigInteger X = g.modPow(Rc,p);
        List<BigInteger> list = new ArrayList<BigInteger>();
        for(int i=0;i<c.size();i++){
            list.add(BigInteger.valueOf(c.get(i).hashCode()).modPow(Rc1,p));
        }

        System.out.println("a:");
        for(int i=0;i<list.size();i++) System.out.println(list.get(i));
        return new OfflineParameter(X,list,Rc,Rc1);
    }

    public S_onlineParameter S_online(OfflineParameter C, OfflineParameter S){
        List<BigInteger> a = C.getList();
        List<BigInteger> ks = S.getList();
        List<BigInteger> al = new ArrayList<BigInteger>();

        for(int i=0;i<a.size();i++){
            al.add(a.get(i).modPow(S.getR1(),p));
        }
        Collections.shuffle(al);

        List<BigInteger> ts = new ArrayList<BigInteger>();
        for(int i=0;i<ks.size();i++){
            ts.add(BigInteger.valueOf((C.getX().modPow(S.getR(),p).multiply(ks.get(i))).hashCode()));
        }

        System.out.println("ts:");
        for(int i=0;i<ts.size();i++) System.out.println(ts.get(i));
        return new S_onlineParameter(S.getX(),al,ts);
    }

    public TestParameter Test(S_onlineParameter S,OfflineParameter C){
        List<BigInteger> a = C.getList();
        List<BigInteger> tc = new ArrayList<BigInteger>();
        List<BigInteger> ts = S.getTs();
        BigDecimal x = new BigDecimal(C.getR1().toString());
        BigDecimal y = BigDecimal.ONE.divide(x,20,BigDecimal.ROUND_DOWN);
        System.out.println("one:"+ y);

        System.out.println("test");
        for(int i=0;i<a.size();i++){

            tc.add(BigInteger.valueOf((S.getY().modPow(C.getR(),p).multiply(S.getA().get(i).modPow(BigDecimal.ONE.divide(x,50,BigDecimal.ROUND_DOWN),p))).hashCode()));
            System.out.println(S.getA().get(i).modPow(BigInteger.ONE.divide(C.getR1()),p));
        }

        System.out.println("tc:");
        for(int i=0;i<tc.size();i++) System.out.println(tc.get(i));
        List<Boolean> tag = new ArrayList<Boolean>();
        boolean flag;
        for(int i=0;i<tc.size();i++){
            flag = false;
            for(int j=0;j<ts.size();j++){
                if(tc.get(i).equals(ts.get(j))){
                    flag=true;
                    break;
                }
            }
            tag.add(flag);
        }
        return new TestParameter(tc,tag);
    }
}

 */