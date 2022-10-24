package cn.edu.buaa.crypto.encryption.ETkpabe;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;

import cn.edu.buaa.crypto.encryption.GT.ELGamal;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ETkpabeEngine {
    private static ETkpabeEngine engine;
    private Pairing pairing;
    private static int A = 10;
    private Element[] X;
    private Element Y1,Y2;
    private Element g;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public static ETkpabeEngine getInstance() {
        if (engine == null) {
            engine = new ETkpabeEngine();
        }
        return engine;
    }
    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
        Element[] x = new Element[A];
        this.X = new Element[A];
        for(int i=0;i<A;i++){
            x[i] = this.pairing.getZr().newRandomElement().getImmutable();
            this.X[i] = g.powZn(x[i]).getImmutable();
        }
        Element y1 = this.pairing.getZr().newRandomElement().getImmutable();
        Element y2 = this.pairing.getZr().newRandomElement().getImmutable();
        this.Y1 = this.pairing.pairing(g,g).powZn(y1).getImmutable();
        this.Y2 = this.pairing.pairing(g,g).powZn(y2).getImmutable();
        return new MasterSecretKey(x,y1,y2);
    }

    public SecretKey KeyGen(MasterSecretKey msk,String accessPolicy,String accessPolicy1,String[] S,String[] S1) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.getY1(), accessControlParameter);

        Map<String, Element> D = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            D.put(rho, this.g.powZn(lambdas.get(rho)).powZn(msk.getX()[Integer.parseInt(rho)].invert()).getImmutable());
        }

        int[][] accessPolicyIntArrays1 = ParserUtils.GenerateAccessPolicy(accessPolicy1);
        String[] rhos1 = ParserUtils.GenerateRhos(accessPolicy1);
        AccessControlParameter accessControlParameter1 = accessControlEngine.generateAccessControl(accessPolicyIntArrays1, rhos1);
        Map<String, Element> lambdas1 = accessControlEngine.secretSharing(pairing, msk.getY2(), accessControlParameter1);

        Map<String, Element> T = new HashMap<String, Element>();
        for (String rho : lambdas1.keySet()) {
            T.put(rho, this.g.powZn(msk.getX()[Integer.parseInt(rho)].invert()).powZn(lambdas1.get(rho)).getImmutable());
        }

        return new SecretKey(D,T,accessPolicy,accessPolicy1);
    }

    public Element getH3(Element M, Element C1, byte[] C2,Element C3,Element[] C4, Element[] C5){
        byte[] mbyte = M.toBytes();
        byte[] c1byte = C1.toBytes();
        byte[] c2byte = C2;
        byte[] c3byte = C3.toBytes();
        byte[][] c4byte = new byte[C4.length][];
        byte[][] c5byte = new byte[C5.length][];
        int len = mbyte.length + c1byte.length + c2byte.length + c3byte.length;
        for(int i=0;i<C4.length;i++){
            c4byte[i] = C4[i].toBytes();
            //System.out.println("i="+C4[i]);
            len += c4byte[i].length;
        }
        for(int i=0;i<C5.length;i++){
            c5byte[i] = C5[i].toBytes();
            len += c5byte[i].length;
        }
        byte[] res = new byte[len];
        System.arraycopy(mbyte,0,res,0,mbyte.length);
        System.arraycopy(c1byte,0,res,mbyte.length,c1byte.length);
        System.arraycopy(c2byte,0,res,mbyte.length+c1byte.length,c2byte.length);
        System.arraycopy(c3byte,0,res,mbyte.length+c1byte.length+c3byte.length,c3byte.length);
        int start = mbyte.length+c1byte.length+c3byte.length;
        for(int i=0;i<c4byte.length;i++){
            System.arraycopy(c4byte[i],0,res,start,c4byte[i].length);
            start+=c4byte[i].length;
        }
        for(int i=0;i<c5byte.length;i++){
            System.arraycopy(c5byte[i],0,res,start,c5byte[i].length);
            start+=c5byte[i].length;
        }
        return PairingUtils.MapByteArrayToGroup(this.pairing,res,PairingUtils.PairingGroupType.G1);
    }

    public CipherText Encrypt(Element message,String[] S,String[] S1){
        Element r1 = this.pairing.getZr().newRandomElement().getImmutable();
        Element r2 = this.pairing.getZr().newRandomElement().getImmutable();
        Element r3 = this.pairing.getZr().newRandomElement().getImmutable();

        Element c1 = this.g.powZn(r1).getImmutable();
        //m||r1
        byte[] mbytes = message.toBytes();
        byte[] rbytes = r1.toBytes();
        byte[] mr = new byte[mbytes.length + rbytes.length];
        System.arraycopy(mbytes,0,mr,0,mbytes.length);
        System.arraycopy(rbytes,0,mr,mbytes.length,rbytes.length);

        //H(sy)
        String S_policy = "";
        for(int i=0;i<S.length;i++) S_policy+=S[i];
        byte[] sbytes = S_policy.getBytes();
        byte[] ybytes = this.Y1.powZn(r2).toBytes();
        byte[] sy = new byte[sbytes.length + ybytes.length];
        System.arraycopy(sbytes,0,sy,0,sbytes.length);
        System.arraycopy(ybytes,0,sy,sbytes.length,ybytes.length);
        Element H_sy = PairingUtils.MapByteArrayToGroup(this.pairing,sy,PairingUtils.PairingGroupType.G1);

        byte[] c2 = PairingUtils.Xor(mr,H_sy.toBytes());

        String S_policy1 = "";
        for(int i=0;i<S1.length;i++) S_policy1+=S1[i];
        byte[] sbytes1 = S_policy1.getBytes();
        byte[] ybytes1 = this.Y2.powZn(r3).getImmutable().toBytes();
        byte[] sy1 = new byte[sbytes1.length + ybytes1.length];
        System.arraycopy(sbytes1,0,sy1,0,sbytes1.length);
        System.arraycopy(ybytes1,0,sy1,sbytes1.length,ybytes1.length);
        Element c3 = message.powZn(r1).mul(
                PairingUtils.MapByteArrayToGroup(this.pairing,sy1,PairingUtils.PairingGroupType.G1)
        ).getImmutable();

        Map<String, Element> c4 = new HashMap<String, Element>();
        Map<String, Element> c5 = new HashMap<String, Element>();
        Element[] C4 = new Element[S.length];
        Element[] C5 = new Element[S1.length];
        int size = 0;
        for(String i : S){
            c4.put(i,this.X[Integer.parseInt(i)].powZn(r2).getImmutable());
            C4[size++] = this.X[Integer.parseInt(i)].powZn(r2).getImmutable();
        }
        size=0;
        for(String j : S1){
            c5.put(j,this.X[Integer.parseInt(j)].powZn(r3).getImmutable());
            C5[size++] = this.X[Integer.parseInt(j)].powZn(r3).getImmutable();
        }

        Element c6 = getH3(message.powZn(r1).getImmutable(),c1,c2,c3,C4,C5);

        return new CipherText(S,S1,c1,c2,c3,c4,c5,c6);
    }

    public Trapdoor TrapdoorGen(String accessPolicy,String[] S,MasterSecretKey msk) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.getY2(), accessControlParameter);

        Map<String, Element> td = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            td.put(rho, this.g.powZn(lambdas.get(rho)).powZn(msk.getX()[Integer.parseInt(rho)].invert()).getImmutable());
        }

        return new Trapdoor(td,accessPolicy);
    }

    public PlainText Decrypt(CipherText ct,SecretKey sk,String[] S, String[] S1) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.S, accessControlParameter);
        Element A = pairing.getGT().newOneElement().getImmutable();

        for(String j : omegaElementsMap.keySet()){
            Element d = sk.getD().get(j);
            Element e = ct.C4.get(j);
            Element lambda = omegaElementsMap.get(j);
            A = A.mul(this.pairing.pairing(d,e).powZn(lambda)).getImmutable();
        }

        String S_policy = "";
        for(int i=0;i<S.length;i++) S_policy+=S[i];
        byte[] sbytes = S_policy.getBytes();
        byte[] ybytes = A.toBytes();
        byte[] sy = new byte[sbytes.length + ybytes.length];
        System.arraycopy(sbytes,0,sy,0,sbytes.length);
        System.arraycopy(ybytes,0,sy,sbytes.length,ybytes.length);
        Element H_sy = PairingUtils.MapByteArrayToGroup(this.pairing,sy,PairingUtils.PairingGroupType.G1).getImmutable();

        byte[] mrbytes = PairingUtils.Xor(ct.C2,H_sy.toBytes());
        byte[] mbytes = Arrays.copyOfRange(mrbytes, 0, 64);
        byte[] rbytes = Arrays.copyOfRange(mrbytes,64,mrbytes.length);
        Element m = this.pairing.getG1().newElementFromBytes(mbytes).getImmutable();
        Element r = this.pairing.getZr().newElementFromBytes(rbytes).getImmutable();

        Element[] c4 = new Element[ct.S.length];
        Element[] c5 = new Element[ct.S1.length];
        int len = 0;
        for(Element x : ct.C4.values()){
            c4[len++] = x;
        }
        len = 0;
        for(Element x : ct.C5.values()){
            c5[len++] = x;
        }

        if(ct.C1.isEqual(this.g.powZn(r))){
            if(ct.C6.isEqual(getH3(m.powZn(r).getImmutable(),ct.C1,ct.C2,ct.C3,c4,c5))){
                return new PlainText(true,m);
            }
        }
        return new PlainText(false,this.pairing.getG1().newZeroElement().getImmutable());
    }

    public TestParameter Test(CipherText CTa,CipherText CTb,Trapdoor TDa,Trapdoor TDb) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(TDa.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(TDa.getAccessPolicy());

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, CTa.S1, accessControlParameter);
        Element A = pairing.getGT().newOneElement().getImmutable();

        for(String j : omegaElementsMap.keySet()){
            Element t = TDa.getTd().get(j);
            Element e = CTa.C5.get(j);
            Element lambda = omegaElementsMap.get(j);
            A = A.mul(this.pairing.pairing(t,e).powZn(lambda)).getImmutable();
        }


        String S_policy = "";
        String[] S1 = CTa.S1;
        for(int i=0;i<S1.length;i++) S_policy+=S1[i];
        byte[] sbytes = S_policy.getBytes();
        byte[] ybytes = A.toBytes();
        byte[] sya = new byte[sbytes.length + ybytes.length];
        System.arraycopy(sbytes,0,sya,0,sbytes.length);
        System.arraycopy(ybytes,0,sya,sbytes.length,ybytes.length);

        Element Ma = CTa.C3.div(
                PairingUtils.MapByteArrayToGroup(this.pairing,sya,PairingUtils.PairingGroupType.G1)
        ).getImmutable();

        int[][] accessPolicyIntArrays1 = ParserUtils.GenerateAccessPolicy(TDb.getAccessPolicy());
        String[] rhos1 = ParserUtils.GenerateRhos(TDb.getAccessPolicy());

        AccessControlParameter accessControlParameter1 = accessControlEngine.generateAccessControl(accessPolicyIntArrays1, rhos1);
        Map<String, Element> omegaElementsMap1 = accessControlEngine.reconstructOmegas(pairing, CTb.S1, accessControlParameter1);
        Element B = pairing.getGT().newOneElement().getImmutable();

        for(String j : omegaElementsMap1.keySet()){
            Element t = TDb.getTd().get(j);
            Element e = CTb.C5.get(j);
            Element lambda = omegaElementsMap1.get(j);
            B = B.mul(this.pairing.pairing(t,e).powZn(lambda)).getImmutable();
        }

        String S_policy1 = "";
        String[] S2 = CTb.S1;
        for(int i=0;i<S2.length;i++) S_policy1+=S2[i];
        byte[] sbytes1 = S_policy1.getBytes();
        byte[] ybytes1 = B.toBytes();
        byte[] syb = new byte[sbytes1.length + ybytes1.length];
        System.arraycopy(sbytes1,0,syb,0,sbytes1.length);
        System.arraycopy(ybytes1,0,syb,sbytes1.length,ybytes1.length);
        Element Mb = CTb.C3.div(
                PairingUtils.MapByteArrayToGroup(this.pairing,syb,PairingUtils.PairingGroupType.G1)
        ).getImmutable();

        Element[] c4_a = new Element[CTa.S.length];
        Element[] c5_a = new Element[CTa.S1.length];
        int len = 0;
        for(Element x : CTa.C4.values()){
            c4_a[len++] = x;
        }
        len = 0;
        for(Element x : CTa.C5.values()){
            c5_a[len++] = x;
        }
        Element[] c4_b = new Element[CTa.S.length];
        Element[] c5_b = new Element[CTa.S1.length];
        len = 0;
        for(Element x : CTb.C4.values()){
            c4_b[len++] = x;
        }
        len = 0;
        for(Element x : CTb.C5.values()){
            c5_b[len++] = x;
        }
        if(CTa.C6.isEqual(getH3(Ma,CTa.C1,CTa.C2,CTa.C3,c4_a,c5_a))){
            if(CTb.C6.isEqual(getH3(Mb,CTb.C1,CTb.C2,CTb.C3,c4_b,c5_b))){
                if(this.pairing.pairing(Ma,CTb.C1).isEqual(this.pairing.pairing(Mb,CTa.C1))){
                    return new TestParameter(true,1);
                }
                return new TestParameter(true,0);
            }
        }
        return new TestParameter(false,-1);
    }
}
