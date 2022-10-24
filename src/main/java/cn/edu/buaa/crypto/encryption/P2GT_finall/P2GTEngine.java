package cn.edu.buaa.crypto.encryption.P2GT_finall;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class P2GTEngine {
    private static P2GTEngine engine;
    private Pairing pairing;
    private Element g,h,ehu,u;
    private int maxnum;
    private PublicKey pk;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();

    public static P2GTEngine getInstance() {
        if (engine == null) {
            engine = new P2GTEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(int n,String perperties){
        this.maxnum = n;
        this.pairing = PairingFactory.getPairing(perperties);
        Element a = this.pairing.getZr().newRandomElement().getImmutable();
        this.u = this.pairing.getG1().newRandomElement().getImmutable();
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
        this.h = this.g.powZn(a).getImmutable();
        this.ehu = this.pairing.pairing(this.h,this.u).getImmutable();
        this.pk = new PublicKey(g,h,ehu,u,maxnum);
        return new MasterSecretKey(a);
    }

    public PublicKey getPk(){
        return this.pk;
    }

    public DecryptionKey KeyGen(String accessPolicy,MasterSecretKey msk) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, msk.getA(), accessControlParameter);

        Map<String, Element> d1 = new HashMap<String, Element>();
        Map<String, Element> d2 = new HashMap<String, Element>();

        for (String rho : lambdas.keySet()) {
            Element r = this.pairing.getZr().newRandomElement().getImmutable();
            d1.put(rho, this.u.powZn(lambdas.get(rho)).mul(PairingUtils.MapStringToGroup(this.pairing,rho,PairingUtils.PairingGroupType.G1).powZn(r)).getImmutable());
            d2.put(rho, this.g.powZn(r).getImmutable());
        }

        return new DecryptionKey(accessPolicy,d1,d2);
    }

    public byte[] AES_KeyGen() throws Exception {
        //初始AES密钥
        byte[] bytes = this.pairing.getGT().newRandomElement().getImmutable().toBytes();
        Element element = pairing.getZr().newElement().setFromHash(bytes,0,bytes.length);
        byte[] aeskey = AESUtil.initKey(new SecureRandom(element.toBytes()));
        return aeskey;
    }
/*
    public CipherText Encrypt(String[] Y,String[] Z,Element message,byte[] kmc) throws Exception {
        byte[] mbytes = message.toBytes();
        byte[] gk = AES_KeyGen();
        byte[] c0 = AESUtil.encryptAES(mbytes,gk);

        Element s = this.pairing.getZr().newRandomElement().getImmutable();
        Element t = this.pairing.getZr().newRandomElement().getImmutable();
        Element c1 = this.pairing.getGT().newElementFromBytes(gk).mul(this.ehu.powZn(s)).getImmutable();
        Element c2 = this.g.powZn(s).getImmutable();
        Element c3 = this.g.powZn(t).getImmutable();
        Map<String, Element> cy = new HashMap<String, Element>();
        Map<String, Element> cz = new HashMap<String, Element>();
        for(String j : Y){
            cy.put(j,PairingUtils.MapStringToGroup(pairing, j, PairingUtils.PairingGroupType.G1).powZn(s).getImmutable());
        }
        for(String j : Z){
            cz.put(j,PairingUtils.MapStringToGroup(pairing, j, PairingUtils.PairingGroupType.G1).powZn(t).getImmutable());
        }

        int splitLength = 16;
        int arrayLength = (int) Math.ceil(mbytes.length / splitLength);
        byte[][] n = new byte[arrayLength][];
        for (int i = 0; i < arrayLength; i++) {

            int from = (int) (i * splitLength);
            int to = (int) (from + splitLength);
            if (to > mbytes.length)
                to = mbytes.length;
            n[i] = Arrays.copyOfRange(mbytes, from, to);
        }

        Element[] e = new Element[arrayLength];
        Element[] e1 = new Element[arrayLength];
        byte[][] pID = new byte[arrayLength][];

        for(int i=0;i<arrayLength;i++){
            Element v = this.pairing.getZr().newRandomElement().getImmutable();
            e[i] = this.u.powZn(v).getImmutable();
            e1[i] = PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1).powZn(v)
                    .mul(PairingUtils.MapByteArrayToGroup(this.pairing,this.ehu.powZn(t).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }
        byte[][] ID = new byte[arrayLength][];
        for(int i=0;i<arrayLength;i++){
            ID[i] = PairingUtils.hash(n[i]);
        }

        for(int i=0;i<arrayLength;i++){
            byte[] nonce = PairingUtils.PF(this.pairing,kmc,ID[i]);
            byte[] data = new byte[nonce.length+ID[i].length];
            System.arraycopy(ID[i],0,data,0,ID[i].length);
            System.arraycopy(nonce,0,data,ID[i].length,nonce.length);
            pID[i] = AESUtil.encryptAES(data,kmc);
        }
        return new CipherText(Y,Z,c0,c1,c2,c3,cy,cz,e,e1,pID);
    }
*/

    public CipherText Encrypt(String[] Y,String[] Z,Element[] message,byte[] kmc) throws Exception {
        //element转bytes
        byte[][] messagebytes = new byte[message.length][];
        int len = 0;
        //System.out.println("bytes:");
        for(int i=0;i<message.length;i++){
            messagebytes[i] = message[i].toBytes();
            //System.out.println(Arrays.toString(messagebytes[i]));
            len += messagebytes[i].length;
        }
        byte[] mbytes = new byte[len];
        int strat=0;
        //bytes数组拼接，传入的element数组大小就是n的大小
        for(int i=0;i<message.length;i++){
            System.arraycopy(messagebytes[i],0,mbytes,strat,messagebytes[i].length);
            strat+=messagebytes[i].length;
        }
        //System.out.println("mbytes:"+Arrays.toString(mbytes));
        byte[] gk = AES_KeyGen();
        byte[] c0 = AESUtil.encryptAES(mbytes,gk);

        Element s = this.pairing.getZr().newRandomElement().getImmutable();
        Element t = this.pairing.getZr().newRandomElement().getImmutable();
        Element c1 = this.pairing.getGT().newElementFromBytes(gk).mul(this.ehu.powZn(s)).getImmutable();
        Element c2 = this.g.powZn(s).getImmutable();
        Element c3 = this.g.powZn(t).getImmutable();
        Map<String, Element> cy = new HashMap<String, Element>();
        Map<String, Element> cz = new HashMap<String, Element>();
        for(String j : Y){
            cy.put(j,PairingUtils.MapStringToGroup(pairing, j, PairingUtils.PairingGroupType.G1).powZn(s).getImmutable());
        }
        for(String j : Z){
            cz.put(j,PairingUtils.MapStringToGroup(pairing, j, PairingUtils.PairingGroupType.G1).powZn(t).getImmutable());
        }

        int arrayLength = message.length;
        byte[][] n = messagebytes;

        Element[] e = new Element[arrayLength];
        Element[] e1 = new Element[arrayLength];
        byte[][] pID = new byte[arrayLength][];

        for(int i=0;i<arrayLength;i++){
            Element v = this.pairing.getZr().newRandomElement().getImmutable();
            e[i] = this.u.powZn(v).getImmutable();
            e1[i] = PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1).powZn(v)
                    .mul(PairingUtils.MapByteArrayToGroup(this.pairing,this.ehu.powZn(t).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }
        byte[][] ID = new byte[arrayLength][];
        for(int i=0;i<arrayLength;i++){
            ID[i] = PairingUtils.hash(n[i]);
        }

        for(int i=0;i<arrayLength;i++){
            byte[] nonce = PairingUtils.PF(this.pairing,kmc,ID[i]);
            byte[] data = new byte[nonce.length+ID[i].length];
            System.arraycopy(ID[i],0,data,0,ID[i].length);
            System.arraycopy(nonce,0,data,ID[i].length,nonce.length);
            pID[i] = AESUtil.encryptAES(data,kmc);
        }
        return new CipherText(Y,Z,c0,c1,c2,c3,cy,cz,e,e1,pID);
    }
    public Element[] Decrypt(CipherText ct,DecryptionKey sk) throws Exception {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.Y, accessControlParameter);
        Element A = pairing.getGT().newOneElement().getImmutable();

        for(String j : omegaElementsMap.keySet()){
            Element d = sk.getD1().get(j);
            Element d1 = sk.getD2().get(j);
            Element cy = ct.Cy.get(j);
            Element lambda = omegaElementsMap.get(j);
            A = A.mul(this.pairing.pairing(ct.C2,d).div(this.pairing.pairing(cy,d1)).powZn(lambda)).getImmutable();
        }

        Element gk1 = ct.C1.div(A).getImmutable();
        byte[] d = gk1.toBytes();
        byte[] gk = new byte[16];
        int len = 0;
        for(int i=0;i<d.length;i++){
            if(d[i]!=0){
                gk[len++] = d[i];
            }
            if(len==16) break;
        }

        byte[] mbytes = AESUtil.decryptAES(ct.C0,gk);
        //System.out.println("mbyte:"+Arrays.toString(mbytes));

        //切割
        int splitLength = 64;
        int arrayLength = (int) Math.ceil(mbytes.length / splitLength);
        byte[][] n = new byte[arrayLength][];
        for (int i = 0; i < arrayLength; i++) {

            int from = (int) (i * splitLength);
            int to = (int) (from + splitLength);
            if (to > mbytes.length)
                to = mbytes.length;
            n[i] = Arrays.copyOfRange(mbytes, from, to);
        }

        Element[] m = new Element[arrayLength];
        for(int i=0;i<arrayLength;i++){
            m[i] = this.pairing.getGT().newElementFromBytes(n[i]);
        }

        return m;
    }
}
