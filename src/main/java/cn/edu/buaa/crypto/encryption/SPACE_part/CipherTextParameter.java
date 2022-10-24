package cn.edu.buaa.crypto.encryption.SPACE_part;

import cn.edu.buaa.crypto.encryption.CPSABE.CipherText;

public class CipherTextParameter {
    public CipherText c;
    public Proof proof;
    public String[] A;
    public Statement statement;
    public CipherTextParameter(CipherText c, Proof proof, String[] A, Statement statement){
        this.c = c;
        this.proof = proof;
        this.A = A;
        this.statement = statement;
    }
}
