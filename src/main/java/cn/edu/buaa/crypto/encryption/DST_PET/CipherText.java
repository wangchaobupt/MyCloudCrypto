package cn.edu.buaa.crypto.encryption.DST_PET;

import java.math.BigInteger;

public class CipherText {
    public BigInteger T1,T2;
    public CipherText(BigInteger t1,BigInteger t2){
        this.T1 = t1;
        this.T2 = t2;
    }

    public int getlen(){
        return T1.toByteArray().length + T2.toByteArray().length;
    }
}
