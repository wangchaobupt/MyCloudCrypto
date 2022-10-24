package cn.edu.buaa.crypto.encryption.KSF_OABE;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;

import cn.edu.buaa.crypto.utils.PairingUtils;
import edu.princeton.cs.algs4.In;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.util.EventListener;
import java.util.HashMap;
import java.util.Map;

public class KSF_OABEEngine {
    private static KSF_OABEEngine engine;
    private Pairing pairing;
    private Element g,g1,g2;
    private Element[] h;
    private int maxnum;
    private String w0;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public static KSF_OABEEngine getInstance() {
        if (engine == null) {
            engine = new KSF_OABEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(int n,String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.maxnum = n;
        Element x = this.pairing.getZr().newRandomElement().getImmutable();
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
        this.g1 = this.g.powZn(x).getImmutable();
        this.g2 = this.pairing.getG1().newRandomElement().getImmutable();
        this.h = new Element[n+1];
        for(int i=0;i<=n;i++){
            this.h[i] = this.pairing.getG1().newRandomElement().getImmutable();
        }
        return new MasterSecretKey(x);
    }

    public initParameter KenGen_init(String accessPolicy, MasterSecretKey msk){
        Element x1 = this.pairing.getZr().newRandomElement().getImmutable();
        Element x2 = msk.getX().sub(x1).getImmutable();
        ok_KGCSPParameter OK_KGCSP = new ok_KGCSPParameter(x1);
        ok_TAParameter OK_TA = new ok_TAParameter(x2);
        return new initParameter(OK_KGCSP,OK_TA);
    }

    public sk_KGCSPParameter KeyGen_out(String accessPolicy, ok_KGCSPParameter OK_KGCSP) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, OK_KGCSP.getX(), accessControlParameter);
        Map<String, Element> d1 = new HashMap<String, Element>();
        Map<String, Element> d2 = new HashMap<String, Element>();

        for (String rho : lambdas.keySet()) {
            Element r = this.pairing.getZr().newRandomElement().getImmutable();
            d1.put(rho, this.g2.powZn(lambdas.get(rho)).mul(this.g1.mul(this.h[Integer.valueOf(rho)]).powZn(r)).getImmutable());
            d2.put(rho, this.g.powZn(r).getImmutable());
        }
        return new sk_KGCSPParameter(d1,d2);
    }

    //SK
    public SKParameter KeyGen_in(ok_TAParameter OK_TA, sk_KGCSPParameter SK_KGCSP,String w){
        Element r = this.pairing.getZr().newRandomElement().getImmutable();
        Element d0 = this.g2.powZn(OK_TA.getX()).mul(this.g1.mul(this.h[0]).powZn(r)).getImmutable();
        Element d1 = this.g.powZn(r).getImmutable();
        sk_TAParameter SK_TA = new sk_TAParameter(d0,d1);
        SKParameter SK = new SKParameter(SK_KGCSP,SK_TA);
        this.w0 = w;
        return SK;
    }

    //KSF_KeyGen
    public BFParameter KeyGen_DU(Element u){
        return new BFParameter(this.g2.powZn(u.invert()).getImmutable());
    }

    public QueryPrivateKey KeyGen_TA(MasterSecretKey msk, String accessPolicy, BFParameter q_BF, TA_StoredParameter TA){
        Map<String, SKParameter> ta = TA.getTa();
        Element gh = ta.get(accessPolicy).getSK_TA().getD0().div(this.g2.powZn(TA.getOK_TA().getX())).getImmutable();
        Element QK = q_BF.getQ().powZn(msk.getX()).mul(gh).getImmutable();
        return new QueryPrivateKey(QK);
    }

    public CipherText Encrypt(Element message, String[] attributes, Element s){
        Element c0 = message.mul(this.pairing.pairing(this.g1,this.g2).powZn(s)).getImmutable();
        Element c1 = this.g.powZn(s);
        Map<String,Element> c= new HashMap<String,Element>();
        for(String i : attributes){
            c.put(i,this.g1.mul(this.h[Integer.valueOf(i)]).powZn(s).getImmutable());
        }
        Element c2 = this.g1.mul(this.h[0]).powZn(s).getImmutable();
        return new CipherText(c0,c1,c,c2,attributes,this.w0);
    }

    public IndexParameter Index(CipherText CT,String[] KW,Element s){
        Element[] k = new Element[KW.length];
        Element[] K = new Element[KW.length];
        for(int i=0;i<KW.length;i++){
            k[i] = this.pairing.pairing(this.g1,this.g2).powZn(s)
                    .mul(this.pairing.pairing(this.g,PairingUtils.MapStringToGroup(this.pairing,KW[i],PairingUtils.PairingGroupType.G1)).powZn(s)).getImmutable();
            K[i] = PairingUtils.MapByteArrayToGroup(this.pairing,k[i].toBytes(), PairingUtils.PairingGroupType.G1).getImmutable();
        }
        return new IndexParameter(CT.getC1(),CT.getC2(),K,K.length);
    }

    public TrapdoorParameter Trapdoor(QueryPrivateKey QK,Element u,String kw, SKParameter SK, String accessPolicy){
        Element tq = PairingUtils.MapStringToGroup(this.pairing,kw,PairingUtils.PairingGroupType.G1).mul(QK.getQK().powZn(u)).getImmutable();
        return new TrapdoorParameter(tq,SK.getSK_KGCSP().getD1(),SK.getSK_KGCSP().getD2(),SK.getSK_TA().getD1().powZn(u).getImmutable(),accessPolicy);
    }

    public TestParameter Test(IndexParameter IX,TrapdoorParameter Td,CipherText CT,IX_StoredParameter IX_CT) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(Td.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(Td.getAccessPolicy());

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, CT.getAttributes(), accessControlParameter);
        Element Q = pairing.getGT().newOneElement().getImmutable();

        for(String j : omegaElementsMap.keySet()){
            Element i0 = Td.getI1().get(j);
            Element i1 = Td.getI2().get(j);
            Element ci = CT.getC().get(j);
            Element lambda = omegaElementsMap.get(j);
            Q = Q.mul(this.pairing.pairing(CT.getC1(),i0).div(this.pairing.pairing(i1,ci)).powZn(lambda)).getImmutable();
        }

        Element k = this.pairing.pairing(IX.getK1(),Td.getTq()).div(this.pairing.pairing(Td.getD1(),IX.getK2())).getImmutable();
        Element hk = PairingUtils.MapByteArrayToGroup(this.pairing,k.toBytes(),PairingUtils.PairingGroupType.G1).getImmutable();

        boolean tag = false;
        for(IndexParameter ix : IX_CT.getIX_CT().keySet()){
            for(int i=0;i<ix.getLen();i++){
                if(hk.isEqual(ix.getK()[i])){
                    tag = true;
                    break;
                }
            }
            return new TestParameter(tag,IX_CT.getIX_CT().get(ix),ix,Q);
        }
        return new TestParameter(tag);
    }

    public Element Decrypt(TestParameter test,sk_TAParameter SK_TA){
        CipherText ct = test.getCT();
        Element m = ct.getC0().mul(this.pairing.pairing(SK_TA.getD1(),ct.getC2()))
                .div(test.getQ().mul(this.pairing.pairing(ct.getC1(),SK_TA.getD0()))).getImmutable();
        return m;
    }
}
