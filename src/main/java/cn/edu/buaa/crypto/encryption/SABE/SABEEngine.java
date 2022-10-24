package cn.edu.buaa.crypto.encryption.SABE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import edu.princeton.cs.algs4.In;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class SABEEngine {
    private static SABEEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Pairing pairing;
    private Element g,ga,egg_alpha,egg_beta;
    private Element[] h;
    private int num;

    private static SABEEngine getInstance(){
        if(engine == null){
            engine = new SABEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(int num,String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        this.num = num;
        g = pairing.getG1().newRandomElement().getImmutable();
        h = new Element[num];
        for(int i=0;i<num;i++){
            h[i] = pairing.getG1().newRandomElement().getImmutable();
        }
        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        ga = g.powZn(a).getImmutable();
        egg_alpha = pairing.pairing(g,g).powZn(alpha).getImmutable();
        egg_beta = pairing.pairing(g,g).powZn(beta).getImmutable();
        return new MasterSecretKey(g.powZn(alpha).getImmutable(),g.powZn(beta).getImmutable());
    }

    public SecretKey KeyGen(MasterSecretKey msk,String[] S){
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element t1 = pairing.getZr().newRandomElement().getImmutable();

        Element gg_alpha = msk.g_alpha.mul(ga.powZn(t)).getImmutable();
        Element gg_beta = msk.g_beta.mul(ga.powZn(t1)).getImmutable();
        Element gt = g.powZn(t).getImmutable();
        Element gt1 = g.powZn(t1).getImmutable();
        Map<String, Element> ht = new HashMap<>();
        Map<String, Element> ht1 = new HashMap<>();
        for(String att : S){
            ht.put(att, h[Integer.valueOf(att)].powZn(t).getImmutable());
            ht1.put(att, h[Integer.valueOf(att)].powZn(t1).getImmutable());
        }
        return new SecretKey(gg_alpha,gg_beta,gt,gt1,ht,ht1,S);
    }

    public CipherText Encrypt(String accessPolicy,Element message) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);

        Map<String, Element> Ds1 = new HashMap<String, Element>();
        Map<String, Element> Ds2 = new HashMap<String, Element>();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Element K =pairing.getGT().newRandomElement().getImmutable();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        Element C0 = PairingUtils.MapByteArrayToGroup(pairing,K.toBytes(),PairingUtils.PairingGroupType.GT).mul(message).getImmutable();
        Element C1 = K.mul(egg_alpha.powZn(s)).getImmutable();
        Element C2 = egg_beta.powZn(s).getImmutable();
        Element D0 = ppp_g.powZn(s).getImmutable();

        String[] S = new String[lambdaElementsMap.keySet().size()];
        int index = 0;
        for(String rho : lambdaElementsMap.keySet()){
            S[index++] = rho;
            Element z = pairing.getZr().newRandomElement().getImmutable();
            Element tmp = ga.powZn(lambdaElementsMap.get(rho)).mul(
                    h[Integer.valueOf(rho)].powZn(z.negate())
            ).getImmutable();
            Ds1.put(rho, tmp);
            Ds2.put(rho, ppp_g.powZn(z).getImmutable());
        }

        return new CipherText(C0,C1,C2,D0,Ds1,Ds2,accessPolicy,S);
    }

    public CipherText Sanitize(CipherText CT) throws Exception {
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        String[] S = CT.attributes;
        Map<String, Element> Ds1 = CT.Ds1;
        Map<String, Element> Ds2 = CT.Ds2;
        Element gg_gamma = g.powZn(gamma).mul(ga.powZn(t)).getImmutable();
        Element gt = g.powZn(t).getImmutable();
        Map<String, Element> ht = new HashMap<>();
        for(String att : S){
            ht.put(att, h[Integer.valueOf(att)].powZn(t).getImmutable());
        }

        PairingPreProcessing ppp_gt = pairing.getPairingPreProcessingFromElement(gt);
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(CT.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(CT.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, S, accessControlParameter);
        Element A = pairing.getGT().newOneElement().getImmutable();
        for(String att : omegaElementsMap.keySet()){
            Element omega = omegaElementsMap.get(att);
            A = A.mul(ppp_gt.pairing(Ds1.get(att)).mul(pairing.pairing(Ds2.get(att),ht.get(att)))
                    .powZn(omega)).getImmutable();
        }
        Element B = pairing.pairing(CT.D0,gg_gamma).div(A).getImmutable();
        if(!B.equals(pairing.pairing(CT.D0,g.powZn(gamma)))){
            throw new Exception("check failed!");
        }

        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element K1 = pairing.getGT().newRandomElement().getImmutable();
        Element V0 = CT.C0.mul(PairingUtils.MapByteArrayToGroup(pairing,K1.toBytes(),PairingUtils.PairingGroupType.GT)).getImmutable();
        Element V1 = CT.C1.mul(egg_alpha.powZn(s)).getImmutable();
        Element V2 = CT.C2.mul(K1.mul(egg_beta.powZn(s))).getImmutable();
        Element V3 = CT.D0.mul(ppp_g.powZn(s)).getImmutable();
        Map<String, Element> As = new HashMap<String, Element>();
        Map<String, Element> Bs = new HashMap<String, Element>();

        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        for(String rho : lambdaElementsMap.keySet()){
            Element z = pairing.getZr().newRandomElement().getImmutable();
            Element tmp = ga.powZn(lambdaElementsMap.get(rho)).mul(
                    h[Integer.valueOf(rho)].powZn(z.negate())
            ).getImmutable();
            As.put(rho, Ds1.get(rho).mul(tmp).getImmutable());
            Bs.put(rho, Ds2.get(rho).mul(ppp_g.powZn(z)).getImmutable());
        }

        return new CipherText(V0,V1,V2,V3,As,Bs,CT.accessPolicy,CT.attributes);
    }

    public Element Decrypt(CipherText CT,SecretKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        Map<String, Element> As = CT.Ds1;
        Map<String, Element> Bs = CT.Ds2;
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(CT.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(CT.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, sk.attributes, accessControlParameter);
        Element e1 = pairing.getGT().newOneElement().getImmutable();
        for(String att : omegaElementsMap.keySet()){
            Element omega = omegaElementsMap.get(att);
            e1 = e1.mul(pairing.pairing(As.get(att),sk.gt).mul(pairing.pairing(Bs.get(att),sk.ht.get(att)))
                    .powZn(omega)).getImmutable();
        }

        Element e2 = pairing.getGT().newOneElement().getImmutable();
        for(String att : omegaElementsMap.keySet()){
            Element omega = omegaElementsMap.get(att);
            e2 = e2.mul(pairing.pairing(As.get(att),sk.gt1).mul(pairing.pairing(Bs.get(att),sk.ht1.get(att)))
                    .powZn(omega)).getImmutable();
        }

        Element d1 = pairing.pairing(CT.D0,sk.gg_alpha).div(e1).getImmutable();
        Element d2 = pairing.pairing(CT.D0,sk.gg_beta).div(e2).getImmutable();
        Element K = CT.C1.div(d1).getImmutable();
        Element K1 = CT.C2.div(d2).getImmutable();
        Element m = CT.C0.div(PairingUtils.MapByteArrayToGroup(pairing,K.toBytes(),PairingUtils.PairingGroupType.GT))
                .div(PairingUtils.MapByteArrayToGroup(pairing,K1.toBytes(),PairingUtils.PairingGroupType.GT)).getImmutable();
        return m;
    }

}
