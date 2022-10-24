package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_RW;

import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.AA_EQSEngine;
import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.AllKey;
import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.PublicKey;
import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.SecretKey;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.AGHO_SPSEngine;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.Signature;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.VerficationKey;
import cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.MasterPublicKey;
import cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.MasterSecretKey;
import cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.RWABACEEngine;
import cn.edu.buaa.crypto.encryption.ASFlow.TABS.SignKey;
import cn.edu.buaa.crypto.encryption.ASFlow.TABS.TABSEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

public class SAACE_RWEngine {
    private static SAACE_RWEngine engine;
    private Pairing pairing;
    private RWABACEEngine engine_ace = RWABACEEngine.getInstance();
    private TABSEngine engine_abs = TABSEngine.getInstance();
    private AGHO_SPSEngine engine_sps = AGHO_SPSEngine.getInstance();
    private AA_EQSEngine engine_eqs = AA_EQSEngine.getInstance();
    private MasterPublicKey mpk;
    private PublicKey evk;
    private cn.edu.buaa.crypto.encryption.ASFlow.TABS.PublicKey avk;
    private VerficationKey svk;
    private CRS crs;

    public static SAACE_RWEngine getInstance(){
        if(engine == null){
            engine = new SAACE_RWEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterKey Setup(String perperties,String[] U,int max){
        MasterSecretKey msk = engine_ace.Setup(perperties);
        mpk = engine_ace.getmpk();
        pairing = engine_ace.getPairing();
        AllKey eqs_allKey = engine_eqs.Setup(pairing, U, mpk.g, mpk.h);
        evk = eqs_allKey.evk;
        cn.edu.buaa.crypto.encryption.ASFlow.TABS.MasterSecretKey ask = engine_abs.Setup(perperties, U);
        avk = engine_abs.avk;
        cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.AllKey sps_allKey = engine_sps.Setup(max, pairing, mpk.g, mpk.h);
        svk = sps_allKey.svk;
        crs = new CRS(mpk.g,mpk.h);
        return new MasterKey(msk,eqs_allKey.esk,ask,sps_allKey.ssk);
    }

    public SecretKey SkGen(MasterKey mk,String[] S){
        return engine_eqs.KeyGen(mk.esk,S);
    }

    public EncryptionKey EKGen(MasterKey mk,String[] T,int t,String[] A){
        SignKey ak = engine_abs.KeyGen(mk.ask, T, t);
        int k = A.length;
        Element[] V = new Element[k];
        Element u = mpk.u;
        Element g = mpk.g;
        for(int i=0;i<k;i++){
            V[i] = u.powZn(pairing.getZr().newRandomElement().getImmutable()).mul(g).getImmutable();
        }
        Signature sign = engine_sps.Sign(mk.ssk, V, T);
        return new EncryptionKey(sign,ak,new PList(T,A,t),V);
    }

    public cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.SecretKey DKGen(MasterKey mk,String[] R){
        return engine_ace.KeyGen(mk.msk,R);
    }

    public SignParameter Sign(SecretKey sk,Element m,String[] B){
        Map<String,Element> v = new HashMap<>();
        for(String att : B){
            Element attElement = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            v.put(att,mpk.g.powZn(attElement).getImmutable());
        }
        cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature sign = engine_eqs.Sign(sk, v, m);
        return new SignParameter(m,B,sign,v);
    }

//    public CipherText Encrypt(SignParameter sm,EncryptionKey ek) throws PolicySyntaxException {
//        String[] A = ek.P.A;
//        String accessPolicy = "";
//        for(int i=0;i<A.length;i++){
//            accessPolicy += A[i];
//            if(i!=A.length-1){
//                accessPolicy += " and ";
//            }
//        }
//
//        cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText c = engine_ace.Encrypt(sm.m, accessPolicy);
//        cn.edu.buaa.crypto.encryption.ASFlow.TABS.SignParameter sign = engine_abs.Sign(ek.ak, c.C, sm.B);
//        Statement statement = new Statement(evk,svk,c,ek.P.T,sm.B,ek.P.A,ek.V,sm.V);
//        statement.init(pairing,crs.g,crs.h);
//        Witness witness = new Witness(sm.m,engine_ace.getS(),ek.sign,sm.sign);
//        Proof proof = NIZK_Prove(statement,witness);
//        return new CipherText(c,ek.P,sm.B,ek.V,sm.V,sign,proof);
//    }

    public CipherText Encrypt(SignParameter sm,EncryptionKey ek) throws PolicySyntaxException {
        String[] A = ek.P.A;
        String accessPolicy = "";
        for(int i=0;i<A.length;i++){
            accessPolicy += A[i];
            if(i!=A.length-1){
                accessPolicy += " and ";
            }
        }

        cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText c = engine_ace.Encrypt(sm.m, accessPolicy);
        cn.edu.buaa.crypto.encryption.ASFlow.TABS.SignParameter sign = engine_abs.Sign(ek.ak, c.C, sm.B);
        return new CipherText(c,ek.P,sm.B,ek.V,sm.V,sign);
    }

    public CipherTextParameter Encrypt_NIZK(CipherText CT, Statement statement,SignParameter sm,EncryptionKey ek){
        Witness witness = new Witness(sm.m,engine_ace.getS(),ek.sign,sm.sign);
        Proof proof = NIZK_Prove(statement,witness);
        return new CipherTextParameter(proof,CT);
    }

    public cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText Sanitize(CipherTextParameter CTparameter,Statement statement) throws Exception {
        CipherText CT = CTparameter.CT;
        cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText c = CT.ct_rw;
        cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText ct;
        if(engine_abs.Verify(c.C,CT.B,CT.sign) && NIZK_Verify(statement,CTparameter.proof)){
            ct = engine_ace.Sanitize(c);
        }else{
            throw new Exception("Sanitize failed!");
        }
        return ct;
    }

    public Element Decrypt(cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.CipherText ct, cn.edu.buaa.crypto.encryption.ASFlow.RWABACE.SecretKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        return engine_ace.Decrypt(sk,ct);
    }

    /*****NIZK Util*****/
    public Statement getStatement(CipherText CT){
        Statement statement = new Statement(evk,svk,CT.ct_rw,CT.P.T,CT.B,CT.P.A,CT.Va,CT.Vb);
        statement.init(pairing,crs.g,crs.h);
        return statement;
    }

    public Proof NIZK_Prove(Statement statement,Witness witness){
        Element g = crs.g;
        Element h = crs.h;
        Element K = mpk.egh_alpha;
        Element Q = statement.Q;
        Element P = statement.P;
        Element R = statement.R;
        Signature mu = witness.mu;
        cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.Signature eta = witness.eta;

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element d = pairing.getZr().newRandomElement().getImmutable();

        Element X = mu.X1.mul(g.powZn(a)).getImmutable();
        Element Y = mu.X0.mul(g.powZn(b)).getImmutable();
        Element Z = mu.X2.mul(h.powZn(b)).getImmutable();
        Element T = mu.X3.mul(h.powZn(a)).getImmutable();
        Element F = eta.Y0.mul(g.powZn(a)).getImmutable();
        Element G = eta.Y1.mul(g.powZn(b)).getImmutable();
        Element H = eta.Y2.mul(h.powZn(b)).getImmutable();
        Element I = eta.Y3.mul(h.powZn(a)).getImmutable();
        Element J = PairingUtils.MapByteArrayToGroup(pairing,witness.m.toBytes(),PairingUtils.PairingGroupType.G2).mul(h.powZn(d)).getImmutable();

        Element r1 = pairing.getZr().newRandomElement().getImmutable();
        Element A = pairing.pairing(g,h).powZn(r1).getImmutable();

        Element r2 = pairing.getZr().newRandomElement().getImmutable();
        Element x2 = pairing.getZr().newRandomElement().getImmutable();
        Element B = K.powZn(x2.add(r2)).getImmutable();

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();
        Element w = pairing.getZr().newRandomElement().getImmutable();
        Element E1 = pairing.pairing(g,svk.V).powZn(x).mul(
                pairing.pairing(g,h).powZn(y)
        ).getImmutable();
        Element E2 = pairing.pairing(X,h).powZn(y).mul(
                pairing.pairing(g,Z).powZn(x)
        ).mul(pairing.pairing(g,h).powZn(z.negate())).getImmutable();
        Element E3 = pairing.pairing(g,
                PairingUtils.MapByteArrayToGroup(pairing,engine_sps.getBytes(statement.T),PairingUtils.PairingGroupType.G2)
        ).powZn(x).mul(pairing.pairing(g,h).powZn(x.negate())).getImmutable();
        Element E4 = pairing.pairing(F,h).powZn(y).mul(
                pairing.pairing(g,H).powZn(x)
        ).mul(pairing.pairing(g,h).powZn(z.negate())).getImmutable();
        Element E5 = pairing.getGT().newOneElement().getImmutable();
        Element E6 = pairing.pairing(G,h).powZn(w).mul(
                pairing.pairing(g,J).powZn(y)
        ).mul(pairing.pairing(g,h).powZn((x.add(z)).negate())).getImmutable();

        CHashParameter Cbytes = new CHashParameter(statement.ct_rw.C,statement.ct_rw.C0,Q,P,R,A,B,E1,E2,E3,E4,E5,E6);
        Element c = PairingUtils.MapByteArrayToGroup(pairing,Cbytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        Element y1 = r1.sub(c.mul(witness.s)).getImmutable();
        Element y2 = r2.sub(c.mul(witness.s)).getImmutable();
        Element n = K.powZn(x2).mul(witness.m.powZn(c.negate())).getImmutable();
        Element t = x.sub(c.mul(a)).getImmutable();
        Element r = y.sub(c.mul(b)).getImmutable();
        Element p = w.sub(d.mul(c)).getImmutable();
        Element o = z.sub(a.mul(b).mul(c)).getImmutable();
        Element q = z.sub(b.mul(d).mul(c)).getImmutable();

        return new Proof(X,Y,Z,T,F,G,H,I,J,c,y1,y2,n,t,r,p,o,q);
    }



    public boolean NIZK_Verify(Statement statement,Proof proof){
        Element g = crs.g;
        Element h = crs.h;
        Element K = mpk.egh_alpha;
        Element Q = statement.Q;
        Element P = statement.P;
        Element R = statement.R;
        Element c = proof.c;

        Element A = pairing.pairing(g,h.powZn(proof.y1).mul(statement.ct_rw.C0.powZn(c))).getImmutable();
        Element B = proof.n.mul(K.powZn(proof.y2).mul(statement.ct_rw.C.powZn(c))).getImmutable();

        Element E1 = pairing.pairing(proof.Y,h).powZn(c).mul(
                pairing.pairing(proof.X,statement.svk.V).powZn(c)
        ).mul(pairing.pairing(g,h).powZn(proof.r)).mul(
                pairing.pairing(g,statement.svk.V).powZn(proof.t)
        ).mul(Q.powZn(c.negate())).getImmutable();

        Element E2 = pairing.pairing(proof.X,proof.Z).powZn(c).mul(
                pairing.pairing(proof.X,h).powZn(proof.r)
        ).mul(pairing.pairing(g,proof.Z).powZn(proof.t)).mul(
                pairing.pairing(g,h).powZn(proof.o.negate())
        ).mul(P.powZn(c.negate())).getImmutable();

        Element hash = PairingUtils.MapByteArrayToGroup(pairing,engine_sps.getBytes(statement.T),PairingUtils.PairingGroupType.G2).getImmutable();
        Element E3 = pairing.pairing(proof.X, hash).powZn(c).mul(
                pairing.pairing(g,proof.T).powZn(c.negate())
        ).mul(pairing.pairing(g,hash).powZn(proof.t)).mul(
                pairing.pairing(g,h).powZn(proof.t.negate())
        ).mul(pairing.getGT().newOneElement().powZn(c.negate())).getImmutable();

        Element E4 = pairing.pairing(proof.F,proof.H).powZn(c).mul(
                pairing.pairing(proof.F,h).powZn(proof.r)
        ).mul(pairing.pairing(g,proof.H).powZn(proof.t)).mul(
                pairing.pairing(g,h).powZn(proof.o.negate())
        ).mul(statement.R.powZn(c.negate())).getImmutable();

        Element E5 = pairing.pairing(proof.G,h).powZn(c).mul(
                pairing.pairing(g,proof.H).powZn(c.negate())
        ).getImmutable();

        Element E6 = pairing.pairing(proof.G,proof.J).powZn(c).mul(
                pairing.pairing(g,proof.I).powZn(c.negate())
        ).mul(pairing.pairing(proof.G,h).powZn(proof.p)).mul(
                pairing.pairing(g,proof.J).powZn(proof.r)
        ).mul(pairing.pairing(g,h).powZn(proof.t.add(proof.q).negate())).mul(
                pairing.getGT().newOneElement().powZn(c.negate())
        ).getImmutable();

        CHashParameter Cbytes = new CHashParameter(statement.ct_rw.C,statement.ct_rw.C0,Q,P,R,A,B,E1,E2,E3,E4,E5,E6);
        Element c1 = PairingUtils.MapByteArrayToGroup(pairing,Cbytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        if(c1.equals(proof.c)){
            return true;
        }
        return false;
    }

}
