package cn.edu.buaa.crypto.encryption.PPGPT;

import java.math.BigInteger;
import java.util.List;

public class OfflineParameter {
    private BigInteger x;
    private List<BigInteger> list;
    private BigInteger R,R1;
    public OfflineParameter(BigInteger x, List<BigInteger> list,BigInteger r,BigInteger r1){
        this.x = x;
        this.list = list;
        this.R = r;
        this.R1 = r1;
    }

    public BigInteger getX() {
        return x;
    }

    public List<BigInteger> getList() {
        return list;
    }

    public BigInteger getR() {
        return R;
    }

    public BigInteger getR1() {
        return R1;
    }
}
