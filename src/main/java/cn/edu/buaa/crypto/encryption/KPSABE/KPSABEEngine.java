package cn.edu.buaa.crypto.encryption.KPSABE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class KPSABEEngine {
    private static KPSABEEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Element g,h,u,v,w,egh_alpha;
    private Pairing pairing;
    private PublicParameter pp;
    private Element s;

    public static KPSABEEngine getInstance(){
        if(engine == null){
            engine = new KPSABEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public PublicParameter getPp(){
        return pp;
    }

    public Element getS(){return s;}

    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG2().newRandomElement().getImmutable();
        u = pairing.getG1().newRandomElement().getImmutable();
        v = pairing.getG1().newRandomElement().getImmutable();
        w = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        egh_alpha = pairing.pairing(g,h).powZn(alpha).getImmutable();
        pp = new PublicParameter(g,h,u,v,w,egh_alpha);
        return new MasterSecretKey(alpha);
    }

    public UserKey Keygen(MasterSecretKey msk,String accessPolicy) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.alpha, accessControlParameter);
        Element a = pairing.getZr().newRandomElement().getImmutable();
        RetrieveKey rk = new RetrieveKey(a);

        Map<String, Element> Ds0 = new HashMap<String, Element>();
        Map<String, Element> Ds1 = new HashMap<String, Element>();
        Map<String, Element> Ds2 = new HashMap<String, Element>();
        for(String rho : lambdas.keySet()){
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Ds0.put(rho, g.powZn(a.mul(lambdas.get(rho))).mul(w.powZn(a.mul(ti))).getImmutable());
            Ds1.put(rho, (u.powZn(elementRho).mul(v)).powZn(a.mul(ti).negate()).getImmutable());
            Ds2.put(rho, h.powZn(a.mul(ti)).getImmutable());
        }
        TransformKey tk = new TransformKey(Ds0,Ds1,Ds2,accessPolicy);
        return new UserKey(tk,rk);
    }

    public CipherText Encrypt(Element m, String[] A, Element[] M){
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.s = s;
        Element C = m.mul(egh_alpha.powZn(s)).getImmutable();
        Element C0 = h.powZn(s).getImmutable();

        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Element ws = w.powZn(s.negate()).getImmutable();
        for(int i=0;i<A.length;i++){
            String att = A[i];
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(att, h.powZn(ri).getImmutable());
            Cs2.put(att, M[i].powZn(ri).mul(ws).getImmutable());
        }
//        for(String att : A){
//            Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
//            Element ri = pairing.getZr().newRandomElement().getImmutable();
//            Cs1.put(att, h.powZn(ri).getImmutable());
//            Cs2.put(att, (u.powZn(elementAtt).mul(v)).powZn(ri).mul(w.powZn(s.negate())).getImmutable());
//        }
        return new CipherText(C,C0,Cs1,Cs2,A);
    }

    public boolean Sanitize_check(CipherText CT,Element[] M){
        String[] A = CT.attributes;
        Map<String, Element> Cs1 = CT.Cs1;
        Map<String, Element> Cs2 = CT.Cs2;
        Element C0 = CT.C0;
        Element k = pairing.getZr().newElement(A.length).getImmutable();
        Element e1 = pairing.getGT().newOneElement().getImmutable();
        Element e2 = pairing.pairing(w.powZn(k),C0).getImmutable();
        Element mul_c2 = pairing.getG1().newOneElement().getImmutable();
        for(int i=0;i<A.length;i++){
            String att = A[i];
            e1 = e1.mul(pairing.pairing(M[i],Cs1.get(att))).getImmutable();
            mul_c2 = mul_c2.mul(Cs2.get(att)).getImmutable();
        }
        if(A.length == Cs1.size() &&
                e1.equals(e2.mul(pairing.pairing(mul_c2,h)))){
            return true;
        }
//        if(A.length == Cs1.size()){
//            for(String att : A){
//                Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
//                if(!pairing.pairing(u.powZn(elementAtt).mul(v),Cs1.get(att)).equals(
//                        pairing.pairing(Cs2.get(att),h).mul(e_wc0)
//                )){
//                    flag = false;
//                    break;
//                }
//            }
//        }else {
//            flag = false;
//        }
        return false;
    }

    public CipherText Sanitize_Rerandom(CipherText CT,Element[] M){
        String[] A = CT.attributes;
        Map<String, Element> Cs1 = CT.Cs1;
        Map<String, Element> Cs2 = CT.Cs2;
        Element C0 = CT.C0;
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element c = CT.C.mul(egh_alpha.powZn(s)).getImmutable();
        Element c0 = C0.mul(h.powZn(s)).getImmutable();

        Map<String, Element> cs1 = new HashMap<String, Element>();
        Map<String, Element> cs2 = new HashMap<String, Element>();
        Element ws = w.powZn(s.negate()).getImmutable();
        ElementPowPreProcessing ppp_h = h.getElementPowPreProcessing();
        for(int i=0;i<A.length;i++){
            String att = A[i];
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            cs1.put(att, Cs1.get(att).mul(ppp_h.powZn(ri)).getImmutable());
            cs2.put(att, Cs2.get(att).mul(M[i].powZn(ri).mul(ws)).getImmutable());
        }
//        for(String att : A){
//            Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
//            Element ri = pairing.getZr().newRandomElement().getImmutable();
//            cs1.put(att, Cs1.get(att).mul(h.powZn(ri)).getImmutable());
//            cs2.put(att, Cs2.get(att).mul((u.powZn(elementAtt).mul(v)).powZn(ri).mul(w.powZn(s.negate()))).getImmutable());
//        }
        return new CipherText(c,c0,cs1,cs2,A);
    }
    /*
    public CipherText Sanitize(CipherText CT) throws Exception {
        String[] A = CT.attributes;
        Map<String, Element> Cs1 = CT.Cs1;
        Map<String, Element> Cs2 = CT.Cs2;
        Element C0 = CT.C0;
        boolean flag = true;
        if(A.length == Cs1.size()){
            for(String att : A){
                Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
                if(!pairing.pairing(u.powZn(elementAtt).mul(v),Cs1.get(att)).equals(
                        pairing.pairing(Cs2.get(att),h).mul(pairing.pairing(w,C0))
                )){
                    flag = false;
                    break;
                }
            }
        }else {
            flag = false;
        }
        if (!flag){
            throw new Exception("check fail!");
        }

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element c = CT.C.mul(egh_alpha.powZn(s)).getImmutable();
        Element c0 = C0.mul(h.powZn(s)).getImmutable();
 
        Map<String, Element> cs1 = new HashMap<String, Element>();
        Map<String, Element> cs2 = new HashMap<String, Element>();
        for(String att : A){
            Element elementAtt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            cs1.put(att, Cs1.get(att).mul(h.powZn(ri)).getImmutable());
            cs2.put(att, Cs2.get(att).mul((u.powZn(elementAtt).mul(v)).powZn(ri).mul(w.powZn(s.negate()))).getImmutable());
        }
        return new CipherText(c,c0,cs1,cs2,A);
    }

     */

    public TransformedCiphertext Transform(CipherText CT, TransformKey tk) throws UnsatisfiedAccessControlException, PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(tk.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(tk.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, CT.attributes, accessControlParameter);

        Element C0 = CT.C0;
        Map<String, Element> Cs1 = CT.Cs1;
        Map<String, Element> Cs2 = CT.Cs2;
        Map<String, Element> Ds0 = tk.Ds0;
        Map<String, Element> Ds1 = tk.Ds1;
        Map<String, Element> Ds2 = tk.Ds2;
        Element B = pairing.getGT().newOneElement().getImmutable();
        for(String att : omegaElementsMap.keySet()){
            B = B.mul(
                    pairing.pairing(Ds0.get(att),C0).mul(pairing.pairing(Ds1.get(att),Cs1.get(att))).mul(pairing.pairing(Cs2.get(att),Ds2.get(att)))
                            .powZn(omegaElementsMap.get(att))
            ).getImmutable();
        }
        return new TransformedCiphertext(CT.C,B);
    }

    public Element Decrypt(TransformedCiphertext rt,RetrieveKey rk){
        Element m = rt.C.div(rt.B.powZn(rk.a.invert())).getImmutable();
        return m;
    }
}
