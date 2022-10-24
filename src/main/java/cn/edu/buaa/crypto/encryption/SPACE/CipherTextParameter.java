package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.encryption.ABS.SignParameter;
import cn.edu.buaa.crypto.encryption.CPSABE.CipherText;

public class CipherTextParameter {
    public CipherText c;
    public Proof proof;
    public SignParameter sigma_m;
    public String[] A,W;
    public Statement statement;
    public CipherTextParameter(CipherText c,Proof proof,SignParameter sigma_m,String[] A,String[] W,Statement statement){
        this.c = c;
        this.proof = proof;
        this.sigma_m = sigma_m;
        this.A = A;
        this.W = W;
        this.statement = statement;
    }
}
