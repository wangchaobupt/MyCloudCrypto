package cn.edu.buaa.crypto.encryption.LargeABS;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class LABSEngine {
    private static LABSEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Pairing pairing;
    private Element g ;
    private int l = 10;
    private int umax = 100;
    private PublicKey pk;

    public static LABSEngine getInstance(){
        if(engine == null){
            engine = new LABSEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public AllKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        this.g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element Y = pairing.pairing(g,g).powZn(alpha).getImmutable();
        Element[] Vx = new Element[umax+1];

        Element[] u = new Element[umax];
        for(int i=0;i<=l;i++){
            u[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        for(int i=0;i<=umax;i++){
            Vx[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        this.pk = new PublicKey(g,Y,Vx,u);
        return new AllKey(pk,new MasterSecretKey(alpha));
    }

    public SecretKey Extract(MasterSecretKey msk,String accessPolicy) throws PolicySyntaxException {
        Element[] Vx = pk.Vx;
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.alpha, accessControlParameter);

        Map<String, Element> D = new HashMap<>();
        Map<String, Element> D1 = new HashMap<>();
        Map<String, Map<String,Element>> D2 = new HashMap<>();
        for(String rho : lambdas.keySet()){
            Element r_i = pairing.getZr().newRandomElement().getImmutable();
            D.put(rho, g.powZn(lambdas.get(rho)).mul(Vx[0].powZn(r_i)));
            D1.put(rho, g.powZn(r_i));
            Map<String, Element> Ds2 = new HashMap<>();
            for(int i=2;i<=umax;i++){
                Ds2.put(String.valueOf(i),Vx[1].powZn(lambdas.get(rho).powZn(pairing.getZr().newElement(i-1)).negate())
                        .mul(Vx[i]).powZn(r_i));
            }
            D2.put(rho, Ds2);
        }
        return new SecretKey(accessPolicy,D,D1,D2);
    }

//    public SignParameter Sign(Element msg, SecretKey sk, String[] W) throws PolicySyntaxException, UnsatisfiedAccessControlException {
//        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.accessPolicy);
//        String[] stringRhos = ParserUtils.GenerateRhos(sk.accessPolicy);
//        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
//        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, W, accessControlParameter);
//
//
//    }


}
