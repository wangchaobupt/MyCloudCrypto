package cn.edu.buaa.crypto.encryption.PMT3;

import java.math.BigInteger;
import java.util.List;

public class OfflineParameter {
    private List<BigInteger> ts;
    public OfflineParameter(List<BigInteger> ts){
        this.ts = ts;
    }

    public List<BigInteger> getTs() {
        return ts;
    }

    public int getlen(){
        int len = 0;
        for(int i=0;i<ts.size();i++) len+=ts.get(i).toByteArray().length;
        return len;
    }
}
