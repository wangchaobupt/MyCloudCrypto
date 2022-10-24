package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.ABS.ABSEngine;
import cn.edu.buaa.crypto.encryption.ABS.AllKey;
import cn.edu.buaa.crypto.encryption.CPSABE.CPSABEEngine;
import cn.edu.buaa.crypto.encryption.CPSABE.CipherText;
import cn.edu.buaa.crypto.encryption.CPSABE.MasterSecretKey;
import cn.edu.buaa.crypto.encryption.CPSABE.PublicKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.LH_SPSEngine;
import cn.edu.buaa.crypto.encryption.LH_SPS.SecretKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SignParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class SPACEEngine {
    private static SPACEEngine engine;
    private Pairing pairing;
    private CPSABEEngine engine0 = new CPSABEEngine();
    private LH_SPSEngine engine_sps = new LH_SPSEngine();
    private ABSEngine engine_abs = new ABSEngine();
    public PublicKey pk_e;
    public cn.edu.buaa.crypto.encryption.LH_SPS.PublicKey vk_s;
    public cn.edu.buaa.crypto.encryption.ABS.PublicKey pk_s;
    public CRS crs;
    private int l = 10;

    public static SPACEEngine getInstance(){
        if(engine == null){
            engine = new SPACEEngine();
        }
        return engine;
    }

    public Pairing getPairing(){
        return pairing;
    }

    public int[] getTau(String s){
        byte[] res = s.getBytes();
        int[] tau = new int[l+1];
        for(int i=1;i<=l;i++){
            tau[i] = res[i] & 1;
        }
        return tau;
    }

    public int[] getTau(Element m){
        byte[] res = m.toBytes();
        int[] tau = new int[l+1];
        for(int i=1;i<=l;i++){
            tau[i] = res[i] & 1;
        }
        return tau;
    }

    public Element getG(){
        return pk_e.g;
    }

    public MasterKey Setup(String perperties,int n){
        MasterSecretKey msk_e = engine0.Setup(perperties);
        pk_e = engine0.getPk();
        pairing = engine0.getPairing();
        AllKey allKey = engine_abs.Setup(perperties);
        pk_s = allKey.mpk;
        cn.edu.buaa.crypto.encryption.LH_SPS.AllKey allKey_sps = engine_sps.KeyGen(pairing, pk_e.h, n);
        vk_s = allKey_sps.pk;
        SecretKey sk_s = allKey_sps.sk;
        crs = new CRS(pk_e.g);
        return new MasterKey(msk_e, allKey.msk, sk_s);
    }

    public EncryptionKey EKGen(MasterKey msk,String[] A,String T) throws PolicySyntaxException {
        cn.edu.buaa.crypto.encryption.ABS.SecretKey sk = engine_abs.Extract(msk.msk_s, T);
        int k = A.length;
        Element[] M = new Element[k];
        for(int i=0;i<k;i++){
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, A[i], PairingUtils.PairingGroupType.Zr);
            M[i] = pk_e.u.powZn(elementAtt).mul(pk_e.v).getImmutable();
        }
        int[] tau = getTau(T);
        SignParameter sign = engine_sps.Sign(vk_s, msk.sk_s, tau, M);
        return new EncryptionKey(T,A,M,sk,sign);
    }

    public cn.edu.buaa.crypto.encryption.ABS.SecretKey EKGen1(MasterKey msk,String T) throws PolicySyntaxException {
        return engine_abs.Extract(msk.msk_s, T);
    }

    public EncryptionKey EKGen2(MasterKey msk, String[] A, String T,cn.edu.buaa.crypto.encryption.ABS.SecretKey sk){
        int k = A.length;
        Element[] M = new Element[k];
        for(int i=0;i<k;i++){
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, A[i], PairingUtils.PairingGroupType.Zr);
            M[i] = pk_e.u.powZn(elementAtt).mul(pk_e.v).getImmutable();
        }
        int[] tau = getTau(T);
        SignParameter sign = engine_sps.Sign(vk_s, msk.sk_s, tau, M);
        return new EncryptionKey(T,A,M,sk,sign);
    }

    public cn.edu.buaa.crypto.encryption.CPSABE.SecretKey DKGEn(MasterKey msk, String[] R){
        return  engine0.KeyGen(msk.msk_e, R);
    }

    public CertifiedMessage Sign(Element m, String[] W, SecretKey sk_o, cn.edu.buaa.crypto.encryption.LH_SPS.PublicKey vk_o){
        int k = W.length;
        Element[] O = new Element[k];
        for(int i=0;i<k;i++){
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, W[i], PairingUtils.PairingGroupType.Zr);
            O[i] = pk_e.u.powZn(elementAtt).mul(pk_e.v).getImmutable();
        }
        int[] tau = getTau(m);
        SignParameter sign = engine_sps.Sign(vk_o,sk_o, tau, O);
        return new CertifiedMessage(m,O,W,sign);
    }

    public CipherTextParameter Encrypt(EncryptionKey ek, CertifiedMessage Cm, cn.edu.buaa.crypto.encryption.LH_SPS.PublicKey vk_o) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        String[] A = ek.attributes;
        String[] W = Cm.W;
        String accessPolicy = "";
        for(String att : A){
            if(att.equals(A[A.length-1]))
                accessPolicy += att;
            else
                accessPolicy += att + " and ";
        }

        CipherText c = engine0.Encrypt(Cm.msg, accessPolicy);

        cn.edu.buaa.crypto.encryption.ABS.SignParameter sigma_m = engine_abs.Sign(c.C, ek.sk, W, A);
        Statement statement = new Statement(pairing,vk_s,vk_o,A,W,accessPolicy,ek.M,Cm.O,c,Cm.sign_w);
        Witness witness = new Witness(Cm.msg, ek.sign_A, engine0.getS());
        Proof proof = NIZK_Prove(statement,witness);
        return new CipherTextParameter(c,proof,sigma_m,A,W,statement);
    }

    public CipherText Encrypt_enc(EncryptionKey ek, CertifiedMessage Cm) throws PolicySyntaxException {
        String[] A = ek.attributes;
        String[] W = Cm.W;
        String accessPolicy = "";
        for(String att : A){
            if(att.equals(A[A.length-1]))
                accessPolicy += att;
            else
                accessPolicy += att + " and ";
        }

        return engine0.Encrypt(Cm.msg, accessPolicy);
    }

    public CipherTextParameter Encrypt_NIZK(Statement statement,CipherText c,EncryptionKey ek, CertifiedMessage Cm) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        String[] A = ek.attributes;
        String[] W = Cm.W;
        cn.edu.buaa.crypto.encryption.ABS.SignParameter sigma_m = engine_abs.Sign(c.C, ek.sk, W, A);
//        Statement statement = new Statement(vk_s,vk_o,A,W,c.accessPolicy,ek.M,Cm.O,c,Cm.sign_w);
//        statement.setPairing(pairing);
        Witness witness = new Witness(Cm.msg, ek.sign_A, engine0.getS());
        Proof proof = NIZK_Prove(statement,witness);
        return new CipherTextParameter(c,proof,sigma_m,A,W,statement);
    }

    public Proof NIZK_Prove(Statement statement, Witness witness){
        Element g = crs.g;
        Element K = pk_e.egg_alpha;
        Element Q = statement.Q;
        Element P = statement.P;
        Element P1 = statement.P1;

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();

        Element X = witness.sigma_A.Z.mul(g.powZn(a)).getImmutable();
        Element Y = witness.sigma_A.R.mul(g.powZn(b)).getImmutable();
        Element Z = witness.sigma_A.U.mul(g.powZn(a)).getImmutable();
        Element W = witness.sigma_A.V.mul(g.powZn(b)).getImmutable();
        Element F = engine_sps.getHash(getTau(witness.m),statement.vk_o.w).mul(g.powZn(a)).getImmutable();

        Element r1 = pairing.getZr().newRandomElement().getImmutable();
        Element X1 = pairing.pairing(g,g).powZn(r1).getImmutable();

        Element r2 = pairing.getZr().newRandomElement().getImmutable();
        Element x2 = pairing.getZr().newRandomElement().getImmutable();
        Element X2 = K.powZn(x2.add(r2)).getImmutable();

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element E1 = pairing.pairing(statement.vk_s.gz,g).powZn(x).mul(pairing.pairing(statement.vk_s.gr,g).powZn(y)).getImmutable();
        Element E2 = pairing.pairing(statement.vk_s.hz,g).powZn(x).mul(pairing.pairing(statement.vk_s.h,g).powZn(x))
                .mul(pairing.pairing(engine_sps.getHash(getTau(statement.accessPolicy),statement.vk_s.w),g).powZn(y)).getImmutable();
        Element E3 = pairing.pairing(g,statement.sigma_w.V).powZn(x).getImmutable();

        CHashParameter CBytes = new CHashParameter(statement.ct.C,statement.ct.C0,Q,P,P1,X1,X2,E1,E2,E3);
        Element c = PairingUtils.MapByteArrayToGroup(pairing,CBytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        Element y1 = r1.sub(c.mul(witness.s)).getImmutable();
        Element y2 = r2.sub(c.mul(witness.s)).getImmutable();
        Element n = K.powZn(x2).mul(witness.m.powZn(c.negate())).getImmutable();
        Element t = x.sub(c.mul(a)).getImmutable();
        Element r = y.sub(c.mul(b)).getImmutable();

        return new Proof(X,Y,Z,W,F,c,y1,y2,n,t,r);
    }

    public boolean NIZK_Verify(Statement statement, Proof proof){
        Element g = crs.g;
        Element c = proof.c;
        Element Q = statement.Q;
        Element P = statement.P;
        Element P1 = statement.P1;
        Element X1 = pairing.pairing(g,g.powZn(proof.y1).mul(statement.ct.C0.powZn(c))).getImmutable();
        Element X2 = proof.n.mul(pk_e.egg_alpha.powZn(proof.y2)).mul(statement.ct.C.powZn(c)).getImmutable();

        Element E1 = pairing.pairing(statement.vk_s.gz,proof.X).powZn(c)
                .mul(pairing.pairing(statement.vk_s.gr,proof.Y).powZn(c))
                .mul(pairing.pairing(statement.vk_s.gz,g).powZn(proof.t))
                .mul(pairing.pairing(statement.vk_s.gr,g).powZn(proof.r))
                .mul(Q.powZn(c.negate())).getImmutable();

        Element E2 = pairing.pairing(statement.vk_s.hz,proof.X).powZn(c)
                .mul(pairing.pairing(statement.vk_s.h,proof.Z).powZn(c))
                .mul(pairing.pairing(engine_sps.getHash(getTau(statement.accessPolicy),statement.vk_s.w),proof.W).powZn(c))
                .mul(pairing.pairing(statement.vk_s.hz,g).powZn(proof.t))
                .mul(pairing.pairing(statement.vk_s.h,g).powZn(proof.t))
                .mul(pairing.pairing(engine_sps.getHash(getTau(statement.accessPolicy),statement.vk_s.w),g).powZn(proof.r))
                .mul(P.powZn(c.negate())).getImmutable();

        Element E3 = pairing.pairing(proof.F, statement.sigma_w.V).powZn(c)
                .mul(pairing.pairing(g,statement.sigma_w.V).powZn(proof.t))
                .mul(P1.powZn(c.negate())).getImmutable();

        CHashParameter CBytes = new CHashParameter(statement.ct.C,statement.ct.C0,Q,P,P1,X1,X2,E1,E2,E3);
        Element c1 = PairingUtils.MapByteArrayToGroup(pairing,CBytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        if(c1.equals(c)){
            return true;
        }
        return false;
    }

    public CipherText Sanitize(CipherTextParameter ct) throws Exception {
        Statement statement = ct.statement;
        CipherText c;

        if(engine0.Sanitize_check(ct.c) && NIZK_Verify(statement,ct.proof)
                && engine_sps.Veriy_first(statement.vk_o,statement.sigma_w,statement.O)
        && engine_abs.Verify(ct.c.C, ct.sigma_m, ct.W, ct.A)){
            c = engine0.Sanitize_Rerandom(ct.c);
        }else{
            throw new Exception("Sanitize failed");
        }
        return c;
    }

    public boolean Sanitize_Verify(CipherTextParameter ct){
        Statement statement = ct.statement;
        return  NIZK_Verify(statement,ct.proof) && engine_sps.Veriy_first(statement.vk_o,statement.sigma_w,statement.O)
                && engine_abs.Verify(ct.c.C, ct.sigma_m, ct.W, ct.A);
    }

    public boolean Sanitize_Check(CipherTextParameter ct){
        return engine0.Sanitize_check(ct.c);
    }

    public CipherText Sanitize_reRandom(CipherTextParameter ct) throws PolicySyntaxException {
        return engine0.Sanitize_Rerandom(ct.c);
    }

    public Element Decrypt(CipherText c, cn.edu.buaa.crypto.encryption.CPSABE.SecretKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        return engine0.Decrypt(c,sk);
    }
}
