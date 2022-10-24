package cn.edu.buaa.crypto.encryption.PPGPT;

import java.math.BigInteger;
import java.util.List;

public class S_onlineParameter {
    private BigInteger Y;
    private List<BigInteger> a;
    private List<BigInteger> ts;
    public S_onlineParameter(BigInteger y,List<BigInteger> a ,List<BigInteger> ts){
        this.Y = y;
        this.a = a;
        this.ts = ts;
    }

    public BigInteger getY() {
        return Y;
    }

    public List<BigInteger> getA() {
        return a;
    }

    public List<BigInteger> getTs() {
        return ts;
    }
}
