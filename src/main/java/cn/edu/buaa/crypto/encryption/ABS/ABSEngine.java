package cn.edu.buaa.crypto.encryption.ABS;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.DSFlow.EncryptionKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

public class ABSEngine {
    private static ABSEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Pairing pairing;
    private Element g ;
    private int l = 10;
    private int umax = 10;
    private PublicKey pk;

    public static ABSEngine getInstance(){
        if(engine == null){
            engine = new ABSEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public byte[] getHbytes(Element msg, Element sigma, String[] W){
        int size = 2 + W.length;
        byte[][] Wbytes = new byte[size][];
        Wbytes[0] = msg.toBytes();
        Wbytes[1] = sigma.toBytes();
        int len = Wbytes[0].length + Wbytes[1].length;
        int idx = 2;
        for(int i=0;i<W.length;i++){
            Wbytes[idx] = W[i].getBytes();
            len += Wbytes[idx].length;
            idx ++;
        }
        byte[] res = new byte[len];
        int start = 0;
        for(int i=0;i<size;i++){
            System.arraycopy(Wbytes[i],0,res,start,Wbytes[i].length);
            start+=Wbytes[i].length;
        }
        return res;
    }

    public int[] getM(byte[] res){
        byte[] shaResult = PairingUtils.hash(res);
        int[] M = new int[l+1];
        for(int i=1;i<=l;i++){
            M[i] = shaResult[i] & 1;
        }
        return M;
    }

    public AllKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        this.g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element Y = pairing.pairing(g,g).powZn(alpha).getImmutable();
        Element T0 = pairing.getG1().newRandomElement().getImmutable();
        Element[] u = new Element[l+1];
        for(int i=0;i<=l;i++){
            u[i] = pairing.getG1().newRandomElement().getImmutable();
        }
        Map<String, Element> Tx = new HashMap<>();
        for(int i=0;i<umax;i++){
            Tx.put(String.valueOf(i),pairing.getG1().newRandomElement().getImmutable());
        }
        this.pk = new PublicKey(g,Y,T0,Tx,u);
        return new AllKey(pk,new MasterSecretKey(alpha));
    }

    public SecretKey Extract(MasterSecretKey msk, String accessPolicy) throws PolicySyntaxException {
        Map<String, Element> Tx = pk.Tx;
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.alpha, accessControlParameter);

        Map<String, Element> D = new HashMap<>();
        Map<String, Element> D1 = new HashMap<>();
        Map<String, Map<String,Element>> D2 = new HashMap<>();
        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        for(String rho : lambdas.keySet()){
            Element r_i = pairing.getZr().newRandomElement().getImmutable();
            D.put(rho, g.powZn(lambdas.get(rho)).mul(pk.T0.mul(Tx.get(rho)).powZn(r_i)));
            D1.put(rho, ppp_g.powZn(r_i));
            Map<String, Element> Ds2 = new HashMap<>();
            for(int i=0;i<umax;i++){
                String att = String.valueOf(i);
                if(att.equals(rho)) continue;
                Ds2.put(att, Tx.get(att).powZn(r_i));
            }
            D2.put(rho, Ds2);
        }
        return new SecretKey(accessPolicy,D,D1,D2);
    }

    public SignParameter Sign(Element msg, SecretKey sk, String[] W) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        Map<String, Element> D = sk.D;
        Map<String, Element> D1 = sk.D1;
        Map<String, Map<String,Element>> D2 = sk.D2;
        Map<String, Element> Tx = pk.Tx;

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(sk.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, W, accessControlParameter);

        ElementPowPreProcessing ppp_g = g.getElementPowPreProcessing();
        Element theta = pairing.getZr().newRandomElement().getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();
        Element sigma1 = ppp_g.powZn(theta).getImmutable();
        Element sigma2 = ppp_g.powZn(delta).getImmutable();

        for(String att : omegaElementsMap.keySet()){
            Element w_i = omegaElementsMap.get(att);
            sigma2 = sigma2.mul(D1.get(att).powZn(w_i)).getImmutable();
        }

        byte[] Hbytes = getHbytes(msg, sigma2, W);
        int[] M = getM(Hbytes);

        Element Dsum = pairing.getG1().newOneElement().getImmutable();
        Element Tsum = pk.T0;
        for(String att : omegaElementsMap.keySet()){
            Element w_i = omegaElementsMap.get(att);
            Element tmp = D.get(att);
            Map<String, Element> Ds2 = D2.get(att);
            for(String x : W){
                if(x.equals(att)) continue;
                tmp = tmp.mul(Ds2.get(x)).getImmutable();
            }
            Dsum = Dsum.mul(tmp.powZn(w_i)).getImmutable();
        }

        for(String att : W){
            Tsum = Tsum.mul(Tx.get(att)).getImmutable();
        }

        Element sigma3 = Dsum.mul(Tsum.powZn(delta)).getImmutable();

        Element[] u = pk.u;
        Element Usum = u[0];
        for(int i=1;i<=l;i++){
            if(M[i] == 0) continue;
            Usum = Usum.mul(u[i]).getImmutable();
        }

        sigma3 = sigma3.mul(Usum.powZn(theta)).getImmutable();

        return new SignParameter(sigma1,sigma2,sigma3);
    }

    public SignParameter Sign(Element msg, SecretKey sk, String[] W,String[] A) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int size = A.length + W.length;
        String[] atts = new String[size];
        for(int i=0;i<A.length;i++){
            atts[i] = A[i];
        }
        for(int i=0;i<W.length;i++){
            atts[i+A.length] = W[i];
        }

        Map<String, Element> D = sk.D;
        Map<String, Element> D1 = sk.D1;
        Map<String, Map<String,Element>> D2 = sk.D2;
        Map<String, Element> Tx = pk.Tx;

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(sk.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, W, accessControlParameter);

        Element theta = pairing.getZr().newRandomElement().getImmutable();
        Element delta = pairing.getZr().newRandomElement().getImmutable();
        Element sigma1 = g.powZn(theta).getImmutable();
        Element sigma2 = g.powZn(delta).getImmutable();

        for(String att : omegaElementsMap.keySet()){
            Element w_i = omegaElementsMap.get(att);
            sigma2 = sigma2.mul(D1.get(att).powZn(w_i)).getImmutable();
        }

        byte[] Hbytes = getHbytes(msg, sigma2, atts);
        int[] M = getM(Hbytes);

        Element Dsum = pairing.getG1().newOneElement().getImmutable();
        Element Tsum = pk.T0;
        for(String att : omegaElementsMap.keySet()){
            Element w_i = omegaElementsMap.get(att);
            Element tmp = D.get(att);
            Map<String, Element> Ds2 = D2.get(att);
            for(String x : W){
                if(x.equals(att)) continue;
                tmp = tmp.mul(Ds2.get(x)).getImmutable();
            }
            Dsum = Dsum.mul(tmp.powZn(w_i)).getImmutable();
        }

        for(String att : W){
            Tsum = Tsum.mul(Tx.get(att)).getImmutable();
        }

        Element sigma3 = Dsum.mul(Tsum.powZn(delta)).getImmutable();

        Element[] u = pk.u;
        Element Usum = u[0];
        for(int i=1;i<=l;i++){
            if(M[i] == 0) continue;
            Usum = Usum.mul(u[i]).getImmutable();
        }

        sigma3 = sigma3.mul(Usum.powZn(theta)).getImmutable();

        return new SignParameter(sigma1,sigma2,sigma3);
    }

    public boolean Verify(Element msg, SignParameter sign, String[] W){
        Map<String, Element> Tx = pk.Tx;
        Element[] u = pk.u;

        byte[] Hbytes = getHbytes(msg, sign.sigma2, W);
        int[] M = getM(Hbytes);

        Element Tsum = pk.T0;

        for(String att : W){
            Tsum = Tsum.mul(Tx.get(att)).getImmutable();
        }

        Element Usum = u[0];
        for(int i=1;i<=l;i++){
            if(M[i] == 0) continue;
            Usum = Usum.mul(u[i]).getImmutable();
        }

        if(pairing.pairing(sign.sigma3,g).equals(
                pk.Y.mul(pairing.pairing(Tsum,sign.sigma2).mul(pairing.pairing(Usum,sign.sigma1)))
        )){
            return true;
        }
        return false;
    }

    public boolean Verify(Element msg, SignParameter sign, String[] W, String[] A){
        int size = A.length + W.length;
        String[] atts = new String[size];
        for(int i=0;i<A.length;i++){
            atts[i] = A[i];
        }
        for(int i=0;i<W.length;i++){
            atts[i+A.length] = W[i];
        }

        Map<String, Element> Tx = pk.Tx;
        Element[] u = pk.u;

        byte[] Hbytes = getHbytes(msg, sign.sigma2, atts);
        int[] M = getM(Hbytes);

        Element Tsum = pk.T0;

        for(String att : W){
            Tsum = Tsum.mul(Tx.get(att)).getImmutable();
        }

        Element Usum = u[0];
        for(int i=1;i<=l;i++){
            if(M[i] == 0) continue;
            Usum = Usum.mul(u[i]).getImmutable();
        }

        if(pairing.pairing(sign.sigma3,g).equals(
                pk.Y.mul(pairing.pairing(Tsum,sign.sigma2).mul(pairing.pairing(Usum,sign.sigma1)))
        )){
            return true;
        }
        return false;
    }
}
