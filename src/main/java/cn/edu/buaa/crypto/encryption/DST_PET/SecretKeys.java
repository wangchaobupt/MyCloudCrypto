package cn.edu.buaa.crypto.encryption.DST_PET;

import java.math.BigInteger;

public class SecretKeys {
    private BigInteger x1,x2;
    public SecretKeys(BigInteger x1,BigInteger x2){
        this.x1 = x1;
        this.x2 = x2;
    }

    public BigInteger getX1() {
        return x1;
    }

    public BigInteger getX2() {
        return x2;
    }
}
