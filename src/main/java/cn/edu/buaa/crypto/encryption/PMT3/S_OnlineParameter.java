package cn.edu.buaa.crypto.encryption.PMT3;

import cn.edu.buaa.crypto.encryption.PPGPT.S_onlineParameter;

import java.math.BigInteger;
import java.util.List;

public class S_OnlineParameter {
    private BigInteger Y;
    private List<BigInteger> a;
    public S_OnlineParameter(BigInteger y,List<BigInteger> a){
        this.Y = y;
        this.a = a;
    }

    public BigInteger getY() {
        return Y;
    }

    public List<BigInteger> getA() {
        return a;
    }

    public int getlen(){
        int len = Y.toByteArray().length;
        for(int i=0;i<a.size();i++) len+=a.get(i).toByteArray().length;
        return len;
    }
}
