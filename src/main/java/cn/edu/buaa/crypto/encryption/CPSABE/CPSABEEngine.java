package cn.edu.buaa.crypto.encryption.CPSABE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class CPSABEEngine {
    private static CPSABEEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Element g,h,u,v,w,egg_alpha;
    private Pairing pairing;
    private PublicKey pk;
    private Element s;

    public static CPSABEEngine getInstance(){
        if(engine == null){
            engine = new CPSABEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public PublicKey getPk(){
        return pk;
    }

    public Element getS(){
        return s;
    }

    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG1().newRandomElement().getImmutable();
        u = pairing.getG1().newRandomElement().getImmutable();
        v = pairing.getG1().newRandomElement().getImmutable();
        w = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        egg_alpha = pairing.pairing(g,g).powZn(alpha).getImmutable();
        this.pk = new PublicKey(g,h,u,v,w,egg_alpha);
        return new MasterSecretKey(alpha);
    }

    public SecretKey KeyGen(MasterSecretKey msk, String[] A){
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element K0 = g.powZn(msk.alpha).mul(w.powZn(r)).getImmutable();
        Element K1 = g.powZn(r).getImmutable();

        Map<String, Element> Ks2 = new HashMap<>();
        Map<String, Element> Ks3 = new HashMap<>();
        Element vr = v.powZn(r.negate()).getImmutable();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_u = u.getElementPowPreProcessing();
        for(String att : A){
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            Ks2.put(att, ppp_g.powZn(ri));
            Ks3.put(att, (ppp_u.powZn(elementAtt).mul(h)).powZn(ri).mul(vr));
        }
        return new SecretKey(A,K0,K1,Ks2,Ks3);
    }

    public CipherText Encrypt(Element m, String accessPolicy) throws PolicySyntaxException {
        s = pairing.getZr().newRandomElement().getImmutable();
        Element C = m.mul(egg_alpha.powZn(s)).getImmutable();
        Element C0 = g.powZn(s).getImmutable();

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Map<String, Element> Cs1 = new HashMap<>();
        Map<String, Element> Cs2 = new HashMap<>();
        Map<String, Element> Cs3 = new HashMap<>();
        String[] attributes = new String[lambdas.size()];
        int idx = 0;
        ElementPowPreProcessing ppp_w = w.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_v = v.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_u = u.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        for(String rho : lambdas.keySet()){
            attributes[idx++] = rho;
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho, ppp_w.powZn(lambdas.get(rho)).mul(ppp_v.powZn(ti)));
            Cs2.put(rho, (ppp_u.powZn(elementRho).mul(h)).powZn(ti.negate()));
            Cs3.put(rho, ppp_g.powZn(ti));
        }
        return new CipherText(accessPolicy,attributes,C,C0,Cs1,Cs2,Cs3);
    }

    public boolean Sanitize_check(CipherText ct){
        Map<String, Element> Cs2 = ct.Cs2;
        Map<String, Element> Cs3 = ct.Cs3;
        String[] attributes = ct.attributes;

        Element A = pairing.getGT().newOneElement().getImmutable();
        Element sumC = pairing.getG1().newOneElement().getImmutable();
        for(String att : attributes){
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            A = A.mul(pairing.pairing(u.powZn(elementAtt).mul(h),Cs3.get(att))).getImmutable();
            sumC = sumC.mul(Cs2.get(att)).getImmutable();
        }
        Element g_neg = g.invert();
        if(A.equals(pairing.pairing(sumC,g_neg))){
            return true;
        }
        return false;
    }

    public CipherText Sanitize_Rerandom(CipherText ct) throws PolicySyntaxException {
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element K = egg_alpha.powZn(s).getImmutable();
        Element T0 = g.powZn(s).getImmutable();

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(ct.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(ct.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Map<String, Element> Ts1 = new HashMap<>();
        Map<String, Element> Ts2 = new HashMap<>();
        Map<String, Element> Ts3 = new HashMap<>();

        ElementPowPreProcessing ppp_w = w.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_v = v.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_u = u.getElementPowPreProcessing();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        for(String rho : lambdas.keySet()){
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Ts1.put(rho, ppp_w.powZn(lambdas.get(rho)).mul(ppp_v.powZn(ti)));
            Ts2.put(rho, (ppp_u.powZn(elementRho).mul(h)).powZn(ti.negate()));
            Ts3.put(rho, ppp_g.powZn(ti));
        }

        Element C = ct.C.mul(K).getImmutable();
        Element C0 = ct.C0.mul(T0).getImmutable();
        Map<String, Element> Cs1 = new HashMap<>();
        Map<String, Element> Cs2 = new HashMap<>();
        Map<String, Element> Cs3 = new HashMap<>();
        Map<String, Element> cs1 = ct.Cs1;
        Map<String, Element> cs2 = ct.Cs2;
        Map<String, Element> cs3 = ct.Cs3;
        for(String rho : Ts1.keySet()){
            Cs1.put(rho, cs1.get(rho).mul(Ts1.get(rho)));
            Cs2.put(rho, cs2.get(rho).mul(Ts2.get(rho)));
            Cs3.put(rho, cs3.get(rho).mul(Ts3.get(rho)));
        }
        return new CipherText(ct.accessPolicy, ct.attributes, C, C0, Cs1,Cs2,Cs3);
    }

    public Element Decrypt(CipherText ct, SecretKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(ct.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(ct.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, sk.attributes, accessControlParameter);

        Map<String, Element> Cs1 = ct.Cs1;
        Map<String, Element> Cs2 = ct.Cs2;
        Map<String, Element> Cs3 = ct.Cs3;
        Map<String, Element> Ks2 = sk.Ks2;
        Map<String, Element> Ks3 = sk.Ks3;
        Element A = pairing.getGT().newOneElement().getImmutable();
        PairingPreProcessing ppp_k = pairing.getPairingPreProcessingFromElement(sk.K1);
        for(String att : omegaElementsMap.keySet()){
            A = A.mul(ppp_k.pairing(Cs1.get(att)))
                    .mul(pairing.pairing(Cs2.get(att),Ks2.get(att)))
                    .mul(pairing.pairing(Cs3.get(att),Ks3.get(att))).powZn(omegaElementsMap.get(att)).getImmutable();
        }
        Element B = pairing.pairing(ct.C0,sk.K0).div(A).getImmutable();
        Element m = ct.C.div(B).getImmutable();
        return m;
    }
}
