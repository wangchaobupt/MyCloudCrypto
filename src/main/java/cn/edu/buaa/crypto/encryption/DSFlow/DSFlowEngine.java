package cn.edu.buaa.crypto.encryption.DSFlow;

import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.AGHO_SPS.*;
import cn.edu.buaa.crypto.encryption.KPSABE.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;

public class DSFlowEngine {
    private static DSFlowEngine engine;
    private Pairing pairing;
    private KPSABEEngine engine0 = new KPSABEEngine();
    private AGHO_SPSEngine engine_sign = new AGHO_SPSEngine();
    public PublicParameter pp;
    public VerificationKey vk;
    public CRS crs;

    public static DSFlowEngine getInstance() {
        if (engine == null) {
            engine = new DSFlowEngine();
        }
        return engine;
    }

    public Pairing getPairing() {
        return this.pairing;
    }


    public MasterKey Setup(int max, String perperties) {
        MasterKey mk = new MasterKey();
        mk.msk = engine0.Setup(perperties);
        pairing = engine0.getPairing();
        pp = engine0.getPp();
        AllKey allkey = engine_sign.KeyGen(max, pairing, pp.g, pp.h);
        vk = allkey.vk;
        mk.sk = allkey.sk;
        crs = NIZK_Gen();
        return mk;
    }

    public EncryptionKey EKGen(MasterKey mk, String[] A) {
        int len = A.length;
        Element[] M = new Element[len];
        Element u = pp.u;
        Element v = pp.v;
        for (int i = 0; i < len; i++) {
            Element elementatt = PairingUtils.MapStringToGroup(pairing, A[i], PairingUtils.PairingGroupType.Zr);
            M[i] = u.powZn(elementatt).mul(v).getImmutable();
        }
        Signature sign = engine_sign.Sign(mk.sk, M);
        return new EncryptionKey(A, M, sign);
    }

    public UserKey DKGen(MasterKey mk, String accessPolicy) throws PolicySyntaxException {
        return engine0.Keygen(mk.msk, accessPolicy);
    }

    public byte[] getCbytes(CHashParameter CBytes) {
        int len = CBytes.getlen();
        byte[][] Cbytes = CBytes.Cbytes;
        byte[] res = new byte[len];
        int strat = 0;
        for (int i = 0; i < 10; i++) {
            System.arraycopy(Cbytes[i], 0, res, strat, Cbytes[i].length);
            strat += Cbytes[i].length;
        }
        return res;
    }


    public CipherText Encrypt_enc(Element m, EncryptionKey ek) {
        return engine0.Encrypt(m, ek.A, ek.M);
    }

    public Element getQ(VerificationKey vk, EncryptionKey ek) {
        Element[] M = ek.M;
        Element[] U = vk.U;
        Element MU = pairing.getGT().newOneElement().getImmutable();
        for (int i = 0; i < M.length; i++) {
            MU = MU.mul(pairing.pairing(M[i], U[i])).getImmutable();
        }
        Element Q = pairing.pairing(pp.g, vk.Z).div(MU).getImmutable();
        return Q;
    }

    public Element getP() {
        return pairing.pairing(pp.g, pp.h).getImmutable();
    }

//    public Statement getstatement(Element P,Element Q,CipherText CT){
//        return new Statement(vk,CT.C0,CT.C,Q,P);
//    }

    public CipherParameter Encrypt_NIZK(CipherText CT, Element m, EncryptionKey ek, Statement statement) {
        Witness witness = new Witness(ek.sign, m, engine0.getS());
        Proof proof = NIZK_Prove(witness, statement);
        return new CipherParameter(CT, proof, ek.M);
    }
    /*
    public CipherParameter Encrypt(Element m, EncryptionKey ek){
        CipherText CT = engine0.Encrypt(m,ek.A,ek.M);
        Statement statement = new Statement(vk,ek.M,CT.C0,CT.C);
        Witness witness = new Witness(ek.sign,m,engine0.getS());
        Proof proof = NIZK_Prove(witness,statement);
        return new CipherParameter(CT,proof,ek.M);
    }
     */

    public boolean Sanitize_Verify(CipherParameter CTParameter, Statement statement) throws Exception {
        if (NIZK_Verify(CTParameter.proof, statement)) {
            return true;
        }
        return false;
    }

    public boolean Sanitize_Check(CipherParameter CTParameter) {
        CipherText CT = CTParameter.ct;
        return engine0.Sanitize_check(CT, CTParameter.M);
    }

    public CipherText Sanitize_reRandom(CipherParameter CTParameter) {
        return engine0.Sanitize_Rerandom(CTParameter.ct, CTParameter.M);
    }
    /*
    public CipherText Sanitize(CipherParameter CTParameter) throws Exception {
        CipherText CT = CTParameter.ct;
        Statement statement = new Statement(vk,CTParameter.M,CT.C0,CT.C);
        CipherText CT1 = CT;
        if(NIZK_Verify(CTParameter.proof,statement)){
            //CT1 = engine0.Sanitize(CT);
            if(engine0.Sanitize_check(CT)){
                CT1 = engine0.Sanitize_Rerandom(CT);
            }else{
                throw new Exception("check fail!");
            }
        }else {
            throw new Exception("Verify failed");
        }
        return CT1;
    }
     */

    public TransformedCiphertext Transform(CipherText CT, TransformKey tk) throws UnsatisfiedAccessControlException, PolicySyntaxException {
        return engine0.Transform(CT, tk);
    }

    public Element Decrypt(TransformedCiphertext rt, RetrieveKey rk) {
        return engine0.Decrypt(rt, rk);
    }


    /***** NIZK *****/
    public CRS NIZK_Gen() {
        Element g0 = pairing.getG1().newRandomElement().getImmutable();
        Element h0 = pairing.getG2().newRandomElement().getImmutable();
        Element egg_gh0 = pairing.pairing(g0, h0).getImmutable();
        return new CRS(g0, h0, egg_gh0);
    }

    public Proof NIZK_Prove(Witness witness, Statement state) {
        Element g = pp.g;
        Element h = pp.h;

        Signature sign = witness.sign;
        Element K = pp.egh_alpha;
        Element Q = state.Q;
        Element P = state.P;

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element X = sign.R.mul(g.powZn(a)).getImmutable();
        Element Y = sign.W.mul(g.powZn(b)).getImmutable();
        Element F = sign.T.mul(h.powZn(b)).getImmutable();

        Element A = crs.g0.powZn(a).getImmutable();
        Element B = crs.h0.powZn(b).getImmutable();

        Element r1 = pairing.getZr().newRandomElement().getImmutable();
//        Element X1 = h.powZn(r1).getImmutable();
        Element X1 = P.powZn(r1).getImmutable();

        Element r2 = pairing.getZr().newRandomElement().getImmutable();
        Element x2 = pairing.getZr().newRandomElement().getImmutable();
        Element X2 = K.powZn(x2.add(r2)).getImmutable();

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();
        Element D1 = crs.g0.powZn(x).getImmutable();
//        Element D2 = crs.h0.powZn(y).getImmutable();
        Element D2 = crs.egg_gh0.powZn(y).getImmutable();
        Element D3 = crs.egg_gh0.powZn(z).getImmutable();
        Element E3 = pairing.pairing(g, vk.V).powZn(x).mul(P.powZn(y)).getImmutable();
        Element E4 = P.powZn(z.negate()).mul(pairing.pairing(g, F).powZn(x))
                .mul(pairing.pairing(X, h).powZn(y)).getImmutable();

        CHashParameter CBytes = new CHashParameter(state.C, state.C0, Q, P, X1, X2, D1, D2, D3, E3, E4);
        Element c = PairingUtils.MapByteArrayToGroup(pairing, getCbytes(CBytes), PairingUtils.PairingGroupType.Zr);

        Element y1 = r1.sub(c.mul(witness.s)).getImmutable();
        Element y2 = r2.sub(c.mul(witness.s)).getImmutable();
        Element n = K.powZn(x2).mul(witness.m.powZn(c.negate())).getImmutable();
        Element t = x.sub(c.mul(a)).getImmutable();
        Element r = y.sub(c.mul(b)).getImmutable();
        Element o = z.sub(c.mul(a).mul(b)).getImmutable();
        return new Proof(X, Y, F, A, B, c, y1, y2, n, t, r, o);
    }
/*
    public boolean NIZK_Verify(Proof proof,Statement state){
        Element g = pp.g;
        Element h = pp.h;

        Element[] U = state.vk.U;
        Element[] M = state.M;
        Element K = pp.egh_alpha;
        VerificationKey vk = state.vk;
        Element MU = pairing.getGT().newOneElement().getImmutable();
        for(int i=0;i<state.M.length;i++){
            MU = MU.mul(pairing.pairing(M[i],U[i])).getImmutable();
        }
        Element Q = pairing.pairing(pp.g,state.vk.Z).div(MU).getImmutable();
        Element P = pairing.pairing(pp.g,pp.h).getImmutable();

//        Element X1 = h.powZn(proof.y1).mul(state.C0.powZn(proof.c)).getImmutable();
        Element X1 = pairing.pairing(g,h.powZn(proof.y1).mul(state.C0.powZn(proof.c))).getImmutable();
        Element X2 = proof.n.mul(K.powZn(proof.y2)).mul(state.C.powZn(proof.c)).getImmutable();
        Element D1 = crs.g0.powZn(proof.t).mul(proof.A.powZn(proof.c)).getImmutable();
//        Element D2 = crs.h0.powZn(proof.r).mul(proof.B.powZn(proof.c)).getImmutable();
        Element D2 = pairing.pairing(crs.g0,crs.h0.powZn(proof.r).mul(proof.B.powZn(proof.c))).getImmutable();
        Element D3 = pairing.pairing(crs.g0,crs.h0).powZn(proof.o).mul(pairing.pairing(proof.A,proof.B).powZn(proof.c)).getImmutable();
        Element E3 = pairing.pairing(proof.X,vk.V).powZn(proof.c).mul(pairing.pairing(proof.Y,h).powZn(proof.c))
                .mul(pairing.pairing(g,vk.V).powZn(proof.t)).mul(pairing.pairing(g,h).powZn(proof.r)).mul(Q.powZn(proof.c.negate())).getImmutable();
        Element E4 = pairing.pairing(proof.X,proof.F).powZn(proof.c).mul(pairing.pairing(g,proof.F).powZn(proof.t))
                .mul(pairing.pairing(proof.X,h).powZn(proof.r)).mul(pairing.pairing(g,h).powZn(proof.o.negate()))
                .mul(P.powZn(proof.c.negate())).getImmutable();

        CHashParameter CBytes = new CHashParameter(state.C,state.C0,Q,P,X1,X2,D1,D2,D3,E3,E4);
        Element c = PairingUtils.MapByteArrayToGroup(pairing,getCbytes(CBytes),PairingUtils.PairingGroupType.Zr);
        if(c.equals(proof.c)){
            return true;
        }
        return false;
    }
 */

    public boolean NIZK_Verify(Proof proof, Statement state) {
        Element g = pp.g;
        Element h = pp.h;
        Element K = pp.egh_alpha;
        VerificationKey vk = state.vk;
        Element Q = state.Q;
        Element P = state.P;

//        Element X1 = h.powZn(proof.y1).mul(state.C0.powZn(proof.c)).getImmutable();
        Element X1 = pairing.pairing(g, h.powZn(proof.y1).mul(state.C0.powZn(proof.c))).getImmutable();
        Element X2 = proof.n.mul(K.powZn(proof.y2)).mul(state.C.powZn(proof.c)).getImmutable();
        Element D1 = crs.g0.powZn(proof.t).mul(proof.A.powZn(proof.c)).getImmutable();
//        Element D2 = crs.h0.powZn(proof.r).mul(proof.B.powZn(proof.c)).getImmutable();
        Element D2 = pairing.pairing(crs.g0, crs.h0.powZn(proof.r).mul(proof.B.powZn(proof.c))).getImmutable();
        Element D3 = pairing.pairing(crs.g0, crs.h0).powZn(proof.o).mul(pairing.pairing(proof.A, proof.B).powZn(proof.c)).getImmutable();

        PairingPreProcessing ppp_gt = pairing.getPairingPreProcessingFromElement(g.powZn(proof.t).getImmutable());
        PairingPreProcessing ppp_X = pairing.getPairingPreProcessingFromElement(proof.X);
        Element E3 = ppp_X.pairing(vk.V).powZn(proof.c).mul(pairing.pairing(proof.Y, h).powZn(proof.c))
                .mul(ppp_gt.pairing(vk.V)).mul(P.powZn(proof.r)).mul(Q.powZn(proof.c.negate())).getImmutable();
        Element E4 = ppp_X.pairing(proof.F).powZn(proof.c).mul(ppp_gt.pairing(proof.F))
                .mul(ppp_gt.pairing(h).powZn(proof.r)).mul(P.powZn(proof.o.negate()))
                .mul(P.powZn(proof.c.negate())).getImmutable();

//        Element E3 = pairing.pairing(proof.X,vk.V).powZn(proof.c).mul(pairing.pairing(proof.Y,h).powZn(proof.c))
//                .mul(pairing.pairing(g,vk.V).powZn(proof.t)).mul(P.powZn(proof.r)).mul(Q.powZn(proof.c.negate())).getImmutable();
//        Element E4 = pairing.pairing(proof.X,proof.F).powZn(proof.c).mul(pairing.pairing(g,proof.F).powZn(proof.t))
//                .mul(pairing.pairing(proof.X,h).powZn(proof.r)).mul(P.powZn(proof.o.negate()))
//                .mul(P.powZn(proof.c.negate())).getImmutable();

        CHashParameter CBytes = new CHashParameter(state.C, state.C0, Q, P, X1, X2, D1, D2, D3, E3, E4);
        Element c = PairingUtils.MapByteArrayToGroup(pairing, getCbytes(CBytes), PairingUtils.PairingGroupType.Zr);
        if (c.equals(proof.c)) {
            return true;
        }
        return false;
    }

}
