package cn.edu.buaa.crypto.encryption.CDABACE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class CDABACEEngine {
    public static CDABACEEngine engine;
    public LSSSLW10Engine accessControlEngine;
    public Pairing pairing;
    public Element g, eggAlpha, gBeta, H, G;
    public Element[] h;
    public PP_ra pp_ra;
    public PP_sa pp_sa;
    public CRS crs;
    public Map<String, Element> Qs = new HashMap<>();
    public Map<String, Element> Ds = new HashMap<>();
    public Map<String, Element> Ps = new HashMap<>();
    public Map<String, Element> Rs = new HashMap<>();

    public static CDABACEEngine getInstance() {
        if (engine == null) {
            engine = new CDABACEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {
        return pairing;
    }

    //1. Setup
    public MSK_ra RASetup(String properties, int U) {
        this.pairing = PairingFactory.getPairing(properties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newElement().getImmutable();
        Element beta = pairing.getZr().newElement().getImmutable();
        h = new Element[U];
        for (int i = 0; i < U; i++) {
            h[i] = pairing.getG1().newRandomElement().getImmutable();
        }
        Element gAlpha = g.powZn(alpha).getImmutable();
        eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        gBeta = g.powZn(beta).getImmutable();

        pp_ra = new PP_ra(g, eggAlpha, gBeta, h);
        return new MSK_ra(gAlpha);
    }

    public MSK_sa SASetup() {
        //SPS
        Element X = pairing.getG1().newRandomElement().getImmutable();
        Element sk = pairing.getZr().newRandomElement().getImmutable();
        Element vk = g.powZn(sk).getImmutable();
        crs = NIZK_Gen(pairing, pp_ra);
        pp_sa = new PP_sa(crs, X, vk);
        return new MSK_sa(sk);
    }

    public DK DKGen(MSK_ra msk_ra, String[] S) {
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element K = msk_ra.gAlpha.mul(gBeta.powZn(t)).getImmutable();
        Element L = g.powZn(t).getImmutable();

        Map<String, Element> K_x = new HashMap<String, Element>();
        for (String attr : S) {
            K_x.put(attr, h[Integer.parseInt(attr)].powZn(t).getImmutable());
        }
        return new DK(K, L, K_x);
    }


    public EK EKGen(MSK_sa msk_sa, String accessPolicy) throws PolicySyntaxException {
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        H = pairing.getG1().newRandomElement().getImmutable();
        G = pairing.getG1().newRandomElement().getImmutable();

        Map<String, Element> eks = new HashMap<String, Element>();

        for (String rho : stringRhos) {
            eks.put(rho, h[Integer.parseInt(rho)].getImmutable());
        }

        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element W = G.powZn(t.invert()).getImmutable();
        Element R = H.powZn(t).getImmutable();
        Map<String, Element> Ss = new HashMap<String, Element>();
        Map<String, Element> Ts = new HashMap<String, Element>();

        for (String rho : eks.keySet()) {
            Element S = eks.get(rho).powZn(msk_sa.v.div(t)).mul(pp_sa.X.powZn(t.invert())).getImmutable();
            Ss.put(rho, S);
            Ts.put(rho, S.powZn(msk_sa.v.div(t)).mul(G.powZn(t.invert())).getImmutable());
        }
        return new EK(accessPolicy, eks, new Sigma(R, Ss, Ts, W));
    }

    public CipherParameter Encryption(Element m, EK ek) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(ek.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(ek.accessPolicy);
        Element s = pairing.getZr().newRandomElement().getImmutable();

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Element C = m.mul(eggAlpha.powZn(s)).getImmutable();
        Element CPrime = g.powZn(s).getImmutable();

        Map<String, Element> Cs = new HashMap<String, Element>();
        Map<String, Element> Ds = new HashMap<String, Element>();
        Map<String, Element> Qs = new HashMap<String, Element>();

        Map<String, Element> Rs = new HashMap<String, Element>();
        Map<String, Element> Ss = new HashMap<String, Element>();
        Map<String, Element> Ts = new HashMap<String, Element>();

        Map<String, Element> tis = new HashMap<String, Element>();
        Map<String, Element> ris = new HashMap<String, Element>();

        for (String rho : lambdaElementsMap.keySet()) {
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            tis.put(rho, ti);
            ris.put(rho, ri);

            Element Ci = gBeta.powZn(lambdaElementsMap.get(rho)).mul(ek.eks.get(rho).powZn(ri.negate())).getImmutable();
            Cs.put(rho, Ci);
            Ds.put(rho, g.powZn(ri).getImmutable());
            //Statement中使用
            Qs.put(rho, gBeta.powZn(lambdaElementsMap.get(rho)).div(Ci).getImmutable());

            Rs.put(rho, ek.sigma.R.powZn(ti.invert()).getImmutable());
            Ss.put(rho, ek.sigma.Ss.get(rho).powZn(ti).getImmutable());
            Element one = pairing.getZr().newOneElement().getImmutable();
            Ts.put(rho, ek.sigma.Ts.get(rho).powZn(ti.mulZn(ti)).mul(ek.sigma.W.powZn(ti.mulZn(one.sub(ti)))).getImmutable());
        }

        SigmaPrime sigmaPrime = new SigmaPrime(Rs, Ss, Ts);
        CipherData ct = new CipherData(ek.accessPolicy, C, CPrime, Cs, Ds);

        //TODO: NIZK Proof
        Statement x = new Statement(sigmaPrime, ct, Qs, ek.eks);
        Witness w = new Witness(ek.sigma, m, s, tis, ris);
        Proof pai = NIZK_Prove(pp_sa, w, x);
        return new CipherParameter(ek.eks, x, pai);
    }

    public CipherData Sanitize(CipherParameter CT){
        // 1. Checking
        SigmaPrime sigmaPrime = CT.x.sigmaPrime;
        CipherData ct = CT.x.ct;

        for (String rho: sigmaPrime.Rs.keySet()) {
            boolean condition1 = pairing.pairing(sigmaPrime.Ss.get(rho), sigmaPrime.Rs.get(rho)).isEqual(
                    pairing.pairing(CT.eks.get(rho), pp_sa.vk).mul(pairing.pairing(pp_sa.X, H)));
            boolean condition2 = pairing.pairing(sigmaPrime.Ts.get(rho), sigmaPrime.Rs.get(rho)).isEqual(
                    pairing.pairing(sigmaPrime.Ss.get(rho), pp_sa.vk).mul(pairing.pairing(G, H))
            );
            // TODO: NIZK.Verify
            boolean condition3 = NIZK_Verify(crs, CT.pai, CT.x);

            if(!condition1 & condition2 & condition3){
                return null;
            }
        }
        // 2. Sanitizing
        Map<String, Element> CPiaos = new HashMap<String, Element>();
        Map<String, Element> DPiaos = new HashMap<String, Element>();
        for (String attr: ct.Cs.keySet()) {
            Element ui = pairing.getZr().newRandomElement().getImmutable();
            CPiaos.put(attr, ct.Cs.get(attr).mul(CT.eks.get(attr).powZn(ui.negate())).getImmutable());
            DPiaos.put(attr, ct.Ds.get(attr).mul(g.powZn(ui)).getImmutable());
        }

        return new CipherData(ct.accessPolicy, ct.C, ct.CPrime, CPiaos, DPiaos);
    }

    public Element Decryption(CipherData st, DK dk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(st.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(st.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, dk.K_x.keySet().toArray(new String[0]), accessControlParameter);

        Element temp1 = pairing.pairing(st.CPrime, dk.K).getImmutable();
        Element temp = pairing.getGT().newOneElement();
        for (String attr: omegaElementsMap.keySet()) {
            Element omega = omegaElementsMap.get(attr);
            temp = temp.mul(pairing.pairing(st.Cs.get(attr), dk.L).mul(
                    pairing.pairing(st.Ds.get(attr), dk.K_x.get(attr))
            ).powZn(omega));
        }
        Element temp2 = temp1.div(temp).getImmutable();
        Element m = st.C.div(temp2).getImmutable();
        return m;
    }

    /*********************NIZK Until*********************/
    
    public CRS NIZK_Gen(Pairing pairing, PP_ra pp_ra){
        this.pairing = pairing;
        this.pp_ra = pp_ra;

        Element g0 = pairing.getG1().newRandomElement().getImmutable();
        return new CRS(g0);
    }

    
    public Proof NIZK_Prove(PP_sa pp_sa, Witness witness, Statement state){
        Element g = pp_ra.g;
        Element K = pp_ra.eggAlpha;
        
        //init
        Qs = state.Qs;
        Ds = state.ct.Ds;
        SigmaPrime sigmaPrime = state.sigmaPrime;
        for (String rho: sigmaPrime.Ss.keySet()) {
            Ps.put(rho, pairing.pairing(sigmaPrime.Ss.get(rho), g).getImmutable());
            Rs.put(rho, pairing.pairing(sigmaPrime.Rs.get(rho), g).getImmutable());
        }

        //(0)
        Sigma sigma = witness.sigma;
        Map<String, Element> Xs = new HashMap<String, Element>();
        Map<String, Element> Ys = new HashMap<String, Element>();
        Map<String, Element> Zs = new HashMap<String, Element>();
        Map<String, Element> Fs = new HashMap<String, Element>();
        Map<String, Element> Gs = new HashMap<String, Element>();
        Map<String, Element> Is = new HashMap<String, Element>();

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element gA = g.powZn(a).getImmutable();
        Element A = crs.g0.powZn(a).getImmutable();

        for (String rho: sigma.Ss.keySet()) {
            Xs.put(rho, sigma.R.mul(gA).getImmutable());
            Ys.put(rho, sigma.Ss.get(rho).mul(gA).getImmutable());
            Zs.put(rho, sigma.Ts.get(rho).mul(gA).getImmutable());
            Fs.put(rho, sigma.W.mul(gA).getImmutable());
            Element gT = g.powZn(witness.tis.get(rho)).getImmutable();
            Gs.put(rho, gT);
            Is.put(rho, gT.powZn(witness.tis.get(rho)).getImmutable());
        }

        //(1)
        Element r1 = pairing.getZr().newRandomElement().getImmutable();
        Element X1 = g.powZn(r1).getImmutable();

        Element r2 = pairing.getZr().newRandomElement().getImmutable();
        Element x2 = pairing.getZr().newRandomElement().getImmutable();
        Element X2 = K.powZn(x2.add(r2)).getImmutable();

        Map<String, Element> X3s = new HashMap<String, Element>();
        Map<String, Element> X4s = new HashMap<String, Element>();
        Map<String, Element> r3s = new HashMap<String, Element>();
        Map<String, Element> r4s = new HashMap<String, Element>();

        Map<String, Element> xs = new HashMap<String, Element>();
        Map<String, Element> E0s = new HashMap<String, Element>();
        Map<String, Element> E1s = new HashMap<String, Element>();
        Map<String, Element> E2s = new HashMap<String, Element>();
        Map<String, Element> E3s = new HashMap<String, Element>();

        for (String rho: state.ct.Cs.keySet()) {
            Element r3 = pairing.getZr().newRandomElement().getImmutable();
            X3s.put(rho, state.eks.get(rho).powZn(r3).getImmutable());
            Element r4 = pairing.getZr().newRandomElement().getImmutable();
            X4s.put(rho, g.powZn(r4).getImmutable());
            r3s.put(rho, r3);
            r4s.put(rho, r4);

            Element x = pairing.getZr().newRandomElement().getImmutable();
            xs.put(rho, x);
            E0s.put(rho, crs.g0.powZn(x).getImmutable());
            E1s.put(rho, pairing.pairing(sigmaPrime.Rs.get(rho).mul(g), g).powZn(x).getImmutable());
            E2s.put(rho, pairing.pairing(Gs.get(rho).mul(Ys.get(rho)), g).powZn(x).getImmutable());
            E3s.put(rho, pairing.pairing(Gs.get(rho), g).powZn(x).getImmutable());
        }

        CHashParameter Cbytes = new CHashParameter(state.ct, X1, X2, X3s, X4s, E0s, E1s, E2s, E3s);
        Element c = PairingUtils.MapByteArrayToGroup(pairing,Cbytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        Element y1 = r1.sub(c.mul(witness.s)).getImmutable();
        Element y2 = r2.sub(c.mul(witness.s)).getImmutable();
        Element n = K.powZn(x2).mul(witness.m.powZn(c.negate())).getImmutable();

        Map<String, Element> y3s = new HashMap<String, Element>();
        Map<String, Element> y4s = new HashMap<String, Element>();
        Map<String, Element> ls = new HashMap<String, Element>();
        Map<String, Element> ps = new HashMap<String, Element>();

        for (String rho: witness.ris.keySet()) {
            y3s.put(rho, r3s.get(rho).sub(witness.ris.get(rho).powZn(c)).getImmutable());
            y4s.put(rho, r4s.get(rho).sub(witness.ris.get(rho).powZn(c)).getImmutable());
            ls.put(rho, xs.get(rho).sub(a.mulZn(c)).getImmutable());
            ps.put(rho, xs.get(rho).sub(witness.tis.get(rho).mulZn(c)).getImmutable());
        }

        return new Proof(Xs, Ys, Zs, Fs, Gs, Is, A, c, y1, y2, y3s, y4s, n, ls, ps);
    }
    
    public boolean NIZK_Verify(CRS crs, Proof proof,Statement state){
        Element c = proof.c;
        SigmaPrime sigmaPrime = state.sigmaPrime;
        Element X1 = g.powZn(proof.y1).mul(state.ct.CPrime.powZn(c)).getImmutable();
        Element X2 = proof.n.mul(eggAlpha.powZn(proof.y2)).mul(state.ct.C.powZn(c)).getImmutable();

        Map<String, Element> X3s = new HashMap<String, Element>();
        Map<String, Element> X4s = new HashMap<String, Element>();

        Map<String, Element> E0s = new HashMap<String, Element>();
        Map<String, Element> E1s = new HashMap<String, Element>();
        Map<String, Element> E2s = new HashMap<String, Element>();
        Map<String, Element> E3s = new HashMap<String, Element>();
        for (String rho: proof.Xs.keySet()) {
            X3s.put(rho, state.eks.get(rho).powZn(proof.y3s.get(rho)).mul(Qs.get(rho).powZn(c)).getImmutable());
            X4s.put(rho, g.powZn(proof.y4s.get(rho)).mul(Ds.get(rho).powZn(c)).getImmutable());

            E0s.put(rho, crs.g0.powZn(proof.ls.get(rho)).mul(proof.A).getImmutable());
//            E1s.put(rho, pairing.pairing(sigmaPrime.Rs.get(rho), g).powZn(proof.ps.get(rho))
//                    .mul(pairing.pairing(proof.Xs.get(rho), g).powZn(c))
//                    .mul(eggAlpha.powZn(proof.ls.get(rho)))
//                    .mul(pairing.getGT().newOneElement().powZn(c)).getImmutable());
//            E2s.put(rho, pairing.pairing(proof.Ys.get(rho), proof.Gs.get(rho)).powZn(c)
//                    .mul(pairing.pairing(g, proof.Gs.get(rho)).powZn(proof.ls.get(rho)))
//                    .mul(pairing.pairing(proof.Ys.get(rho),g).powZn(proof.ps.get(rho)))
//                    .mul(pairing.pairing(proof.Ys.get(rho), proof.Gs.get(rho)).powZn(c))
//                    .mul(Ps.get(rho).powZn(c.negate())).getImmutable());
//            E3s.put(rho, pairing.pairing(proof.Zs.get(rho), proof.Is.get(rho)).powZn(c)
//                    .mul(pairing.pairing(proof.Fs.get(rho), proof.Gs.get(rho)).powZn(c))
//                    .mul(pairing.pairing(g, proof.Gs.get(rho)).powZn(proof.ls.get(rho)))
//                    .mul(pairing.pairing(proof.Fs.get(rho), proof.Is.get(rho)).powZn(c.negate()))
//                    .mul(Rs.get(rho).powZn(c.negate())).getImmutable());

            PairingPreProcessing ppp_g = pairing.getPairingPreProcessingFromElement(g.getImmutable());
            PairingPreProcessing ppp_G = pairing.getPairingPreProcessingFromElement(proof.Gs.get(rho).getImmutable());
            PairingPreProcessing ppp_I = pairing.getPairingPreProcessingFromElement(proof.Is.get(rho).getImmutable());
            Element gL = g.powZn(proof.ls.get(rho)).getImmutable();
            Element tempE1 = sigmaPrime.Rs.get(rho).powZn(proof.ps.get(rho)).mul(proof.Xs.get(rho).powZn(c))
                    .mul(gL).getImmutable();
            Element Yc = proof.Ys.get(rho).powZn(c).getImmutable();
            Element tempE2 = Yc.mul(Yc).mul(gL).getImmutable();
            Element tempE3_1 = proof.Zs.get(rho).powZn(c).mul(proof.Fs.get(rho).powZn(c.negate())).getImmutable();
            Element tempE3_2 = proof.Fs.get(rho).powZn(c).mul(gL).getImmutable();

            E1s.put(rho, ppp_g.pairing(tempE1).mul(pairing.getGT().newOneElement().powZn(c)).getImmutable());
            E2s.put(rho, ppp_G.pairing(tempE2).mul(pairing.pairing(proof.Ys.get(rho),g.powZn(proof.ps.get(rho)))).mul(Ps.get(rho).powZn(c.negate())).getImmutable());
            E3s.put(rho, ppp_I.pairing(tempE3_1).mul(ppp_G.pairing(tempE3_2)).mul(Rs.get(rho).powZn(c.negate())).getImmutable());
        }
        CHashParameter Cbytes = new CHashParameter(state.ct, X1, X2, X3s, X4s, E0s, E1s, E2s, E3s);
        Element cPrime = PairingUtils.MapByteArrayToGroup(pairing,Cbytes.getCbytes(),PairingUtils.PairingGroupType.Zr);

        if(cPrime.equals(proof.c)){
            return true;
        }
        return false;
    }


    public byte[] getCbytes(CHashParameter CBytes){
        int len = CBytes.getlen();
        byte[][] Cbytes = CBytes.Cbytes;
        byte[] res = new byte[len];
        int strat = 0;
        for(int i=0;i<10;i++){
            System.arraycopy(Cbytes[i],0,res,strat,Cbytes[i].length);
            strat+=Cbytes[i].length;
        }
        return res;
    }



}
