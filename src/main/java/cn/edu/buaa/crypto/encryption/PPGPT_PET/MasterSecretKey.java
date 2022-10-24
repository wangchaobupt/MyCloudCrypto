package cn.edu.buaa.crypto.encryption.PPGPT_PET;

import java.math.BigInteger;

public class MasterSecretKey {
    private BigInteger lambda;
    public MasterSecretKey(BigInteger lambda){
        this.lambda = lambda;
    }

    public BigInteger getLambda() {
        return lambda;
    }

    public int getlen(){
        return lambda.toByteArray().length;
    }
}
