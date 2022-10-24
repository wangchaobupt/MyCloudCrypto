package cn.edu.buaa.crypto.encryption.ABACEHAN;

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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class ABACEHANEngine {
    private static ABACEHANEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Element g,eta,h,h_1,h_2,Y;
    private Element[] H;
    private Pairing pairing;

    public static ABACEHANEngine getInstance(){
        if(engine == null){
            engine = new ABACEHANEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public boolean intersection(String[] S,String[] R){
        HashSet<String> set1 = new HashSet<String>();
        for(String i:S){
            set1.add(i);
        }
        HashSet<String> set2 = new HashSet<String>();
        for(String i:R){
            if(set1.contains(i))
                set2.add(i);
        }
        if(set2.size() == R.length) return true;
        else return false;
    }

    public byte[] getCTbytes(CipherText CT){
        int size = 3+2*CT.attributes.length;
        int len = 0;
        byte[][] CTbytes = new byte[size][];
        CTbytes[0] = CT.C.toBytes();
        CTbytes[1] = CT.C1.toBytes();
        CTbytes[2] = CT.C2.toBytes();
        int i = 3;
        for(String rho:CT.Cs.keySet()){
            CTbytes[i++] = CT.Cs.get(rho).toBytes();
        }
        for(String rho:CT.Ds.keySet()){
            CTbytes[i++] = CT.Ds.get(rho).toBytes();
        }
        for(i=0;i<size;i++){
            len += CTbytes[i].length;
        }
        byte[] res = new byte[len];
        int strat = 0;
        for(i=0;i<size;i++){
            System.arraycopy(CTbytes[i],0,res,strat,CTbytes[i].length);
            strat+=CTbytes[i].length;
        }
        return res;
    }

    public AllSecretKey Setup(String perperties,int l){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        eta = pairing.getG1().newRandomElement().getImmutable();
        Element a,alpha,gamma,theta;
        a = pairing.getZr().newRandomElement().getImmutable();
        alpha = pairing.getZr().newRandomElement().getImmutable();
        gamma = pairing.getZr().newRandomElement().getImmutable();
        theta = pairing.getZr().newRandomElement().getImmutable();
        H = new Element[l];
        for(int i=0;i<l;i++){
            H[i] = pairing.getG1().newRandomElement().getImmutable();
        }
        h = pairing.pairing(g,g).powZn(alpha).getImmutable();
        h_1 = g.powZn(a).getImmutable();
        h_2 = g.powZn(gamma).getImmutable();
        Y = g.powZn(theta).getImmutable();

        return new AllSecretKey(new MasterSecretKey(a,alpha,gamma),new SanSercetKey(theta));
    }

    public SecretKey KeyGen(String ID,String[] A,MasterSecretKey msk){
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element H_ID = PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.Zr);
        Element K = g.powZn(msk.getAlpha()).mul(g.powZn(msk.getA().mul(t))).mul(
                eta.powZn(msk.getGamma().add(H_ID).invert())
        ).getImmutable();
        Element L = g.powZn(t).getImmutable();
        Element R = g.powZn(msk.getGamma().add(H_ID).invert()).getImmutable();
        Map<String, Element> K_x = new HashMap<String, Element>();
        for(String att : A){
            K_x.put(att,H[Integer.parseInt(att)].powZn(t).getImmutable());
        }
        return new SecretKey(K,L,R,K_x,A,ID);
    }

    public CipherParameter Encryption(Element m,SecretKey sk,String accessPolicy) throws Exception {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);

        Map<String, Element> Cs = new HashMap<String, Element>();
        Map<String, Element> Ds = new HashMap<String, Element>();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        Element C = m.mul(h.powZn(s)).mul(
                pairing.pairing(g,Y).powZn(s.negate())
        ).getImmutable();
        Element C1 = ppp_g.powZn(s).getImmutable();
        Element C2 = eta.powZn(s).mul(Y.powZn(s)).getImmutable();
        String[] omg = new String[lambdaElementsMap.keySet().size()];
        int i = 0;
        for (String rho : lambdaElementsMap.keySet()){
            omg[i] = rho;
            i++;
            Element r = pairing.getZr().newRandomElement().getImmutable();
//            Element tmp_c = h_1.powZn(lambdaElementsMap.get(rho)).mul(
//                H[Integer.parseInt(rho)].powZn(r.negate())
//            ).mul(Y.powZn(r.negate())).getImmutable();
            Element tmp_c = h_1.powZn(lambdaElementsMap.get(rho)).mul(
                    H[Integer.parseInt(rho)].mul(Y).powZn(r.negate())
            ).getImmutable();
            Cs.put(rho,tmp_c);
            Ds.put(rho,ppp_g.powZn(r).getImmutable());
        }
        CipherText CT = new CipherText(C,C1,C2,Cs,Ds,accessPolicy,omg);

        String[] A = sk.getAttributes();
        if(!intersection(A,omg)){
            throw new Exception("As not satisfy omg");
        }
        String[] As = omg;
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();
        Element w = pairing.getZr().newRandomElement().getImmutable();
        Element K = sk.getK().mul(h_1.powZn(t)).getImmutable();
        Element L1 = sk.getL().mul(ppp_g.powZn(t)).getImmutable();
        Element H_CT = PairingUtils.MapByteArrayToGroup(this.pairing,getCTbytes(CT),PairingUtils.PairingGroupType.Zr);
        Element L2 = L1.powZn(H_CT).mul(eta.powZn(w)).getImmutable();
        Element L3 = ppp_g.powZn(w).getImmutable();
        Element R1 = sk.getR().powZn(z).getImmutable();
        Element R2 = eta.powZn(z.invert()).getImmutable();
        Element R3 = ppp_g.powZn(z.invert()).getImmutable();
        Element H_id = PairingUtils.MapStringToGroup(this.pairing, sk.getID(),PairingUtils.PairingGroupType.Zr);
        Element R4 = h_2.mul(ppp_g.powZn(H_id)).powZn(z.invert()).getImmutable();
        Element R5 = pairing.pairing(g,g).powZn(H_id.div(z)).getImmutable();
        Element R6 = pairing.getG1().newOneElement().getImmutable();
        for(String att:As){
            R6 = R6.mul(sk.getK_x().get(att).mul(H[Integer.parseInt(att)].powZn(t)).getImmutable());
        }
        HeadData Hd = new HeadData(K,L1,L2,L3,R1,R2,R3,R4,R5,R6);
        return new CipherParameter(CT,Hd,As);
    }

    public SanCipherText Sanitizer(CipherParameter CTParameter,SanSercetKey ssk) throws Exception {
        CipherText CT = CTParameter.CT;
        HeadData Hd = CTParameter.Hd;
        String[] As = CTParameter.As;
        Element H_CT = PairingUtils.MapByteArrayToGroup(this.pairing,getCTbytes(CT),PairingUtils.PairingGroupType.Zr);
        Element H_x = pairing.getG1().newOneElement().getImmutable();
        for(String att:As){
            H_x = H_x.mul(H[Integer.parseInt(att)]);
        }
        SanCipherText CT1 = new SanCipherText();
        PairingPreProcessing ppp_g = pairing.getPairingPreProcessingFromElement(g);
        if(As.equals(CT.attributes) &&
                ppp_g.pairing(Hd.K).equals(h.mul(pairing.pairing(Hd.L1,h_1)).mul(pairing.pairing(Hd.R1,Hd.R2))) &&
                ppp_g.pairing(Hd.R2).equals(pairing.pairing(eta,Hd.R3)) &&
                ppp_g.pairing(Hd.R4).equals(pairing.pairing(h_2,Hd.R3).mul(Hd.R5)) &&
                pairing.pairing(Hd.R1,Hd.R4).equals(ppp_g.pairing(g)) &&
                ppp_g.pairing(Hd.L2).equals(ppp_g.pairing(Hd.L1).powZn(H_CT).mul(pairing.pairing(Hd.L3,eta))) &&
                ppp_g.pairing(Hd.R6).equals(pairing.pairing(H_x,Hd.L1))

        ){
            Element r = pairing.getZr().newRandomElement().getImmutable();
            CT1.C = CT.C.mul(
                    pairing.pairing(g,CT.C1).powZn(ssk.getTheta())
            ).mul(h.powZn(r)).getImmutable();
            CT1.C1 = CT.C1.mul(g.powZn(r)).getImmutable();
            CT1.C2 = CT.C2.mul(CT.C1.powZn(ssk.getTheta().negate())).mul(eta.powZn(r)).getImmutable();
            CT1.C3 = h_1.powZn(r).getImmutable();

            Map<String, Element> Cs = CT.Cs;
            Map<String, Element> Ds = CT.Ds;
            Map<String, Element> Cs1 = new HashMap<String, Element>();
            Map<String, Element> Ds1 = new HashMap<String, Element>();

            ElementPowPreProcessing epp_g = g.getElementPowPreProcessing();
            for(String rho:Cs.keySet()){
                Cs1.put(rho,Cs.get(rho).mul(Ds.get(rho).powZn(ssk.getTheta())).mul(H[Integer.parseInt(rho)].powZn(r.negate())).getImmutable());
                Ds1.put(rho,Ds.get(rho).mul(epp_g.powZn(r)).getImmutable());
            }

            CT1.Cs = Cs1;
            CT1.Ds = Ds1;

            CT1.accessPolicy = CT.accessPolicy;
            CT1.attributes = CT.attributes;
        }else {
            throw new Exception("not pass");
        }
        return CT1;
    }

    public Element Decryption(SecretKey sk,SanCipherText CT) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        Element d1 = pairing.pairing(CT.C1,sk.getK()).getImmutable();
        Element d2 = pairing.getGT().newOneElement();
        Element d3 = pairing.pairing(sk.getL(),CT.C3).getImmutable();
        Element d4 = pairing.pairing(sk.getR(),CT.C2).getImmutable();
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(CT.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(CT.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, sk.getAttributes(), accessControlParameter);
        for(String att:omegaElementsMap.keySet()){
            Element lambda = omegaElementsMap.get(att);
            d2 = d2.mul(pairing.pairing(CT.Cs.get(att),sk.getL()).mul(
                    pairing.pairing(CT.Ds.get(att),sk.getK_x().get(att))
            ).powZn(lambda));
        }

        Element D = d1.div(
                d2.mul(d3).mul(d4)
        ).getImmutable();
        Element m = CT.C.div(D).getImmutable();
        return m;
    }
}
