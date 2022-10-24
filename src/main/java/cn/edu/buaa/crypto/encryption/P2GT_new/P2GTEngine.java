package cn.edu.buaa.crypto.encryption.P2GT_new;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Element;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class P2GTEngine {
    private static P2GTEngine engine;
    private Element g,h,u,w,ega;
    private Pairing pairing;
    private AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
    private PublicKey pk;

    public static P2GTEngine getInstance() {
        if (engine == null) {
            engine = new P2GTEngine();
        }
        return engine;
    }
    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
        this.u = this.pairing.getG1().newRandomElement().getImmutable();
        this.h = this.pairing.getG1().newRandomElement().getImmutable();
        this.w = this.pairing.getG1().newRandomElement().getImmutable();
        Element a = this.pairing.getZr().newRandomElement().getImmutable();
        this.ega = this.pairing.pairing(this.g,this.g).powZn(a).getImmutable();
        this.pk = new PublicKey(g,h,u,w,ega);
        return new MasterSecretKey(a);
    }

    public PublicKey getPk(){return this.pk;}

    public byte[] AES_KeyGen() throws Exception {
        //初始AES密钥
        byte[] bytes = this.pairing.getGT().newRandomElement().getImmutable().toBytes();
        Element element = pairing.getZr().newElement().setFromHash(bytes,0,bytes.length);
        byte[] aeskey = AESUtil.initKey(new SecureRandom(element.toBytes()));
        return aeskey;
    }

    public DecryptionKey KeyGen(String accessPolicy,MasterSecretKey msk) throws PolicySyntaxException {
        SKGen skGen = new SKGen();
        skGen.init(this.pairing);
        return skGen.generateSK(accessPolicy,msk,pk);
    }

    public CipherText Encrypt(String[] Y,String[] Z,Element[] message,byte[] kmc) throws Exception {
        CipherGen cipherGen = new CipherGen();
        cipherGen.init(this.pairing);
        return cipherGen.generateCT(Y,Z,message,kmc,pk);
    }

    public Element[] Decrypt(CipherText ct, DecryptionKey sk, String[] attributes) throws Exception {
        DecGen decGen = new DecGen();
        decGen.init(this.pairing);
        return decGen.generaterDec(ct,sk,attributes);
    }
}
