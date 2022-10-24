package cn.edu.buaa.crypto.encryption.PMT3;

import java.math.BigInteger;
import java.util.List;

public class C_OnlineParameter {
    private List<BigInteger> a;
    public C_OnlineParameter(List<BigInteger> a){
        this.a = a;
    }

    public List<BigInteger> getA() {
        return a;
    }

    public int getlen(){
        int len = 0;
        for(int i=0;i<a.size();i++) len+=a.get(i).toByteArray().length;
        return len;
    }
}
