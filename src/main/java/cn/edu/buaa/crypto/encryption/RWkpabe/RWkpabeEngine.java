package cn.edu.buaa.crypto.encryption.RWkpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
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

public class RWkpabeEngine {
    private static RWkpabeEngine engine;
    private Pairing pairing;
    private Element g,u,h,w,v,ega;
    private AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();

    public static RWkpabeEngine getInstance() {
        if (engine == null) {
            engine = new RWkpabeEngine();
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
        this.v = this.pairing.getG1().newRandomElement().getImmutable();
        Element a = this.pairing.getZr().newRandomElement().getImmutable();
        this.ega = this.pairing.pairing(this.g,this.g).powZn(a).getImmutable();
        return new MasterSecretKey(a);
    }

    public SecretKey KeyGen(MasterSecretKey msk,String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        Map<String, Element> K0s = new HashMap<String, Element>();
        Map<String, Element> K1s = new HashMap<String, Element>();
        Map<String, Element> K2s = new HashMap<String, Element>();

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, msk.a, accessControlParameter);
        for (String rho : lambdaElementsMap.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Element K0 = this.g.powZn(lambdaElementsMap.get(rho)).mul(this.w.powZn(ti)).getImmutable();
            K0s.put(rho, K0);
            Element K1 = this.u.powZn(elementRho).mul(this.h).powZn(ti.negate()).getImmutable();
            K1s.put(rho, K1);
            Element K2 = this.g.powZn(ti).getImmutable();
            K2s.put(rho, K2);
        }
        return new SecretKey(accessPolicy,K0s,K1s,K2s);
    }

    public CipherText Encrypt(Element message,String[] attributes){
        Element s = this.pairing.getZr().newRandomElement().getImmutable();
        Element C = message.mul(this.ega.powZn(s)).getImmutable();
        Element C0 = this.g.powZn(s).getImmutable();
        Map<String, Element> C1 = new HashMap<String, Element>();
        Map<String, Element> C2 = new HashMap<String, Element>();

        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element c1 = this.g.powZn(ri).getImmutable();
            C1.put(attribute, c1);
            Element c2 = this.u.powZn(elementAttribute).mul(this.h).powZn(ri)
                    .mul(this.w.powZn(s.negate())).getImmutable();
            C2.put(attribute, c2);
        }
        return new CipherText(attributes,C,C0,C1,C2);
    }

    public Element Decrypt(CipherText ct,SecretKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(sk.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.getAttributes(), accessControlParameter);
        Element B = pairing.getGT().newOneElement().getImmutable();
        for (String attribute : omegaElementsMap.keySet()) {
            Element C0 = ct.getC0();
            Element K0 = sk.K0.get(attribute);
            Element C1 = ct.getC1().get(attribute);
            Element K1 = sk.K1.get(attribute);
            Element C2 = ct.getC2().get(attribute);
            Element K2 = sk.K2.get(attribute);
            Element lambda = omegaElementsMap.get(attribute);
            B = B.mul(pairing.pairing(C0, K0).mul(pairing.pairing(C1, K1)).mul(pairing.pairing(C2, K2)).powZn(lambda)).getImmutable();
        }
        return ct.getC().div(B).getImmutable();
    }


}
