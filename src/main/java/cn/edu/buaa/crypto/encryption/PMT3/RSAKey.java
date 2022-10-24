package cn.edu.buaa.crypto.encryption.PMT3;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class RSAKey {

    private RSAPublicKey publicKey;

    private RSAPrivateKey privateKey;


    public RSAPublicKey getPublicKey() {
        return publicKey;
    }


    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }


    public RSAKey(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }




}
