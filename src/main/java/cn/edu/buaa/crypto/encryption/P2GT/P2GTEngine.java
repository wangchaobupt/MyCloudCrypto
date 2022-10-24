package cn.edu.buaa.crypto.encryption.P2GT;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.HashMap;
import java.util.Map;

public class P2GTEngine {
    private static P2GTEngine engine;
    private Pairing pairing;
    private Element g,h,f,eg;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public static P2GTEngine getInstance() {
        if (engine == null) {
            engine = new P2GTEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
        Element beta = this.pairing.getZr().newRandomElement().getImmutable();
        Element a = this.pairing.getZr().newElement().getImmutable();
        Element ga = this.g.powZn(a).getImmutable();

        this.h = this.g.powZn(beta).getImmutable();
        this.f = this.g.powZn(beta.invert()).getImmutable();
        this.eg = this.pairing.pairing(this.g,this.g).powZn(a).getImmutable();
        return new MasterSecretKey(beta,ga);
    }

    public DecryptionKey KeyGen(MasterSecretKey mk,String[] attributes){
        Element r = this.pairing.getZr().newRandomElement().getImmutable();
        Element D = mk.getGa().mul(this.g.powZn(r)).powZn(mk.getBeta().invert()).getImmutable();
        Map<String, Element> D1 = new HashMap<String, Element>();
        Map<String, Element> D2 = new HashMap<String, Element>();
        for(String attribute : attributes){
            Element hj = PairingUtils.MapStringToGroup(this.pairing,attribute,PairingUtils.PairingGroupType.G1);
            Element rj = this.pairing.getZr().newRandomElement().getImmutable();
            D1.put(attribute,this.g.powZn(r).mul(hj.powZn(rj)).getImmutable());
            D2.put(attribute,this.g.powZn(rj).getImmutable());
        }
        return new DecryptionKey(D,D1,D2,attributes);
    }

    public CipherText Encrypt(Element message, String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element ega = this.eg.powZn(s).getImmutable();
        Element c = this.h.powZn(s).getImmutable();
        Element c0 = message.mul(ega).getImmutable();
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Map<String, Element> c1 = new HashMap<String, Element>();
        Map<String, Element> c2 = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            c1.put(rho, this.g.powZn(lambdas.get(rho)).getImmutable());
            c2.put(rho, PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.G1).powZn(lambdas.get(rho)).getImmutable());
        }

        return new CipherText(accessPolicy,c0,c,c1,c2);
    }

    public Element Decrypt(DecryptionKey sk,CipherText ct) throws PolicySyntaxException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(ct.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(ct.getAccessPolicy());
        Element m;
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, sk.getAttributes(), accessControlParameter);
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element D1 = sk.getD1().get(attribute);
                Element D2 = sk.getD2().get(attribute);
                Element C1 = ct.getC1s().get(attribute);
                Element C2 = ct.getC2s().get(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(D1, C1).div(pairing.pairing(D2, C2)).powZn(lambda)).getImmutable();
            }
            m = ct.getC0().div(pairing.pairing(ct.getC(), sk.getD()).div(A).getImmutable());
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
        return m;
    }

}
