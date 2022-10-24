package cn.edu.buaa.crypto.encryption.PMT3;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

/**
 * rsa工具类
 * @author ydy
 * */
public class RSAUtils {

    private  static final String SIGN_SHA1="SHA1WithRSA";
    /**
     * 初始化rsa钥匙
     *
     * */
    public static RSAKey initkeys(){

        try {
            //rsa工厂
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //长度
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //公钥
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            System.out.println("n:"+rsaPublicKey.getModulus());
            System.out.println("e:"+rsaPublicKey.getPublicExponent());
            //私钥
            RSAPrivateKey rsaPrivateKey=(RSAPrivateKey) keyPair.getPrivate();
            System.out.println("d:"+rsaPrivateKey.getPrivateExponent());
            RSAKey rsaKeys=new RSAKey(rsaPublicKey, rsaPrivateKey);
            return rsaKeys;
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }
    /**
     * 获取公钥
     * @param publicKeyStr
     * */
    public static RSAPublicKey getPublicKey(String publicKeyStr){
        try {
            KeyFactory keyFactory=KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(Base64.decodeBase64(publicKeyStr));
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(pkcs8EncodedKeySpec);
            return rsaPublicKey;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 获取私钥
     * @param privateKeyStr
     * */
    public static RSAPrivateKey getPrivateKey(String privateKeyStr){
        try {
            KeyFactory keyFactory=KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyStr));
            RSAPrivateKey privateKey=(RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 私钥解密
     * @param contentBytes
     * @param privateKey
     * */
    public static byte[] decrypt(byte[] contentBytes,RSAPrivateKey privateKey){
        try {

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(contentBytes);
        }catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }
    /**
     * 公钥加密
     * @param contentBytes
     * @param rsaPublicKey
     * */
    public static byte[] encrypt(byte[] contentBytes,RSAPublicKey rsaPublicKey){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,rsaPublicKey);
            return cipher.doFinal(contentBytes);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 数字签名
     * @param contentBytes 待签名数据
     * @param privateKey 私钥
     * */
    public static byte[] signSHA1(byte[] contentBytes,RSAPrivateKey privateKey){
        try {
            Signature signature=Signature.getInstance(SIGN_SHA1);
            signature.initSign(privateKey);
            signature.update(contentBytes);
            return signature.sign();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return null;
    }
    /**
     * 验证数字签名
     * @param contentBytes 数据
     * @param signBytes 签名数据
     * @param publicKey 公钥
     * */
    public boolean verifySHA1(byte[] contentBytes,byte[] signBytes,RSAPublicKey publicKey){
        try {
            Signature signature=Signature.getInstance(SIGN_SHA1);
            signature.initVerify(publicKey);
            signature.update(contentBytes);
            return signature.verify(signBytes);
        }  catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return false;
    }

    public static void main(String[] args)  {
        RSAKey rsakeys = initkeys();
        RSAPublicKey rsaPublicKey = rsakeys.getPublicKey();
        String publicKeyStr=Base64.encodeBase64String(rsaPublicKey.getEncoded());
        System.out.println("公钥");
        System.out.println(publicKeyStr);
        System.out.println("-------------------------------------------------------------------------------------------------");

        RSAPrivateKey rsaPrivateKey = rsakeys.getPrivateKey();
        String privateKeyStr = Base64.encodeBase64String(rsaPrivateKey.getEncoded());
        System.out.println("私钥");
        System.out.println(privateKeyStr);

        String str="我的测试";
        System.out.println("开始加密");
        byte[] decodeBase64 = Base64.encodeBase64(StringUtils.getBytesUtf8(str));
        //加密
        byte[] enByte=	encrypt(decodeBase64, rsaPublicKey);
        //解密
        byte[] deByte=decrypt(enByte, rsaPrivateKey);
        byte[] strByte = Base64.decodeBase64(deByte);
        String strResult=   StringUtils.newString(strByte, "utf-8");
        System.out.println(strResult);




    }



}