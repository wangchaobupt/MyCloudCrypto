package cn.edu.buaa.crypto.encryption.ASFlow.RWABACE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class RWABACEEngine {
    private static RWABACEEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Element g,u,h,w,v,egh_alpha;
    private Pairing pairing;
    private Element s;

    public static RWABACEEngine getInstance(){
        if(engine == null){
            engine = new RWABACEEngine();
        }
        return engine;
    }

    public MasterPublicKey getmpk(){
        return new MasterPublicKey(g,u,h,w,v,egh_alpha);
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(String perperties){
        pairing = PairingFactory.getPairing(perperties);
        accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG2().newRandomElement().getImmutable();
        u = pairing.getG1().newRandomElement().getImmutable();
        v = pairing.getG1().newRandomElement().getImmutable();
        w = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        egh_alpha = pairing.pairing(g,h).powZn(alpha).getImmutable();
        return new MasterSecretKey(alpha);
    }

    public SecretKey KeyGen(MasterSecretKey msk,String[] R){
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element D0 = g.powZn(msk.alpha).mul(w.powZn(r)).getImmutable();
        Element D1 = h.powZn(r).getImmutable();
        Map<String, Element> Ds2 = new HashMap<String, Element>();
        Map<String, Element> Ds3 = new HashMap<String, Element>();
        for (String att : R){
            Element elementatt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Ds2.put(att,h.powZn(ri).getImmutable());
            Ds3.put(att,(u.powZn(elementatt).mul(g)).powZn(ri).mul(v.powZn(r.negate())).getImmutable());
        }
        return new SecretKey(D0,D1,Ds2,Ds3,R);
    }

    public CipherText Encrypt(Element m,String accessPolicy) throws PolicySyntaxException {
        s = pairing.getZr().newRandomElement().getImmutable();
        Element C = m.mul(egh_alpha.powZn(s)).getImmutable();
        Element C0 = h.powZn(s).getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element t_i = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho,w.powZn(lambdas.get(rho)).mul(v.powZn(t_i)));
            Cs2.put(rho,u.powZn(elementRho).mul(g).powZn(t_i.negate()));
            Cs3.put(rho,h.powZn(t_i));
        }
        return new CipherText(accessPolicy,C,C0,Cs1,Cs2,Cs3);
    }

    public Element getS(){
        return this.s;
    }
    public CipherText Sanitize(CipherText ct) throws PolicySyntaxException {
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element C = ct.C.mul(egh_alpha.powZn(s)).getImmutable();
        Element C0 = ct.C0.mul(h.powZn(s)).getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(ct.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(ct.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        Map<String, Element> cs1 = ct.Cs1;
        Map<String, Element> cs2 = ct.Cs2;
        Map<String, Element> cs3 = ct.Cs3;
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element t_i = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho,cs1.get(rho).mul(w.powZn(lambdas.get(rho)).mul(v.powZn(t_i))));
            Cs2.put(rho,cs2.get(rho).mul(u.powZn(elementRho).mul(g).powZn(t_i.negate())));
            Cs3.put(rho,cs3.get(rho).mul(h.powZn(t_i)));
        }
        return new CipherText(ct.accessPolicy,C,C0,Cs1,Cs2,Cs3);
    }

    public Element Decrypt(SecretKey sk,CipherText CT) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        Map<String, Element> Cs1 = CT.Cs1;
        Map<String, Element> Cs2 = CT.Cs2;
        Map<String, Element> Cs3 = CT.Cs3;
        Map<String, Element> Ds2 = sk.Ds2;
        Map<String, Element> Ds3 = sk.Ds3;

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(CT.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(CT.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, sk.attributes, accessControlParameter);
        Element D = pairing.getGT().newOneElement().getImmutable();
        for (String att : omegaElementsMap.keySet()) {
            Element w_i = omegaElementsMap.get(att);
            D = D.mul((pairing.pairing(Cs1.get(att),sk.D1).mul(pairing.pairing(Cs2.get(att),Ds2.get(att)))
                    .mul(pairing.pairing(Ds3.get(att),Cs3.get(att)))).powZn(w_i)).getImmutable();
        }
        Element Y = pairing.pairing(sk.D0,CT.C0).div(D).getImmutable();
        Element m = CT.C.div(Y).getImmutable();
        return m;
    }
}
