package cn.edu.buaa.crypto.encryption.PPGPT;

import java.math.BigInteger;
import java.util.List;

public class TestParameter {
    private List<BigInteger> tc;
    private List<Boolean> tag;
    public TestParameter(List<BigInteger> tc, List<Boolean> tag){
        this.tag = tag;
        this.tc = tc;
    }

    public List<Boolean> getTag() {
        return tag;
    }

    public List<BigInteger> getTc() {
        return tc;
    }
}
