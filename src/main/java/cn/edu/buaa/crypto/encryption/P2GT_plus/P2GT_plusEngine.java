package cn.edu.buaa.crypto.encryption.P2GT_plus;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.P2GT_finall.AESUtil;
import cn.edu.buaa.crypto.encryption.P2GT_finall.P2GTEngine;

import cn.edu.buaa.crypto.utils.PairingUtils;
import com.sun.javafx.collections.ElementObservableListDecorator;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class P2GT_plusEngine {
    private static P2GT_plusEngine engine;
    private static P2GTEngine engine0;
    private Pairing pairing;
    private cn.edu.buaa.crypto.encryption.P2GT_finall.PublicKey pk;
    private Element ur,gu;
    private PublicKey PK;

    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    public static P2GT_plusEngine getInstance(){
        if(engine == null){
            engine = new P2GT_plusEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(String perperties,int n){
        this.engine0 = new P2GTEngine();
        cn.edu.buaa.crypto.encryption.P2GT_finall.MasterSecretKey msk = engine0.Setup(n, perperties);
        this.pk = engine0.getPk();
        this.pairing = engine0.getPairing();
        Element r = this.pairing.getZr().newRandomElement().getImmutable();
        Element u = this.pairing.getZr().newRandomElement().getImmutable();
        this.ur = this.pk.u.powZn(r).getImmutable();
        this.gu = this.pk.g.powZn(u).getImmutable();
        this.PK = new PublicKey(this.pk,this.ur,this.gu);
        return new MasterSecretKey(msk,r,u);
    }

    public PublicKey getPK() {
        return PK;
    }

    public DecryptionKey KeyGen(String accessPolicy, MasterSecretKey msk, String id) throws PolicySyntaxException {
        cn.edu.buaa.crypto.encryption.P2GT_finall.DecryptionKey sk = engine0.KeyGen(accessPolicy,msk.getMsk());
        Element x = this.pairing.getZr().newRandomElement().getImmutable();
        Element k = this.gu.powZn(msk.getR()).mul(
                PairingUtils.MapStringToGroup(this.pairing,id,PairingUtils.PairingGroupType.G1).powZn(x)
        ).getImmutable();
        Element k1 = this.pk.u.powZn(x).getImmutable();
        return new DecryptionKey(sk,k,k1);
    }

    public byte[] AES_KeyGen() throws Exception {
        //初始AES密钥
        byte[] bytes = this.pairing.getGT().newRandomElement().getImmutable().toBytes();
        Element element = pairing.getZr().newElement().setFromHash(bytes,0,bytes.length);
        byte[] aeskey = AESUtil.initKey(new SecureRandom(element.toBytes()));
        return aeskey;
    }

    public CipherText Encrypt(String[] Y,String[] Z,String id,Element[] message,byte[] kmc) throws Exception {

        //CT
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
        for(int i=0;i<message.length;i++){
            System.arraycopy(messagebytes[i],0,mbytes,strat,messagebytes[i].length);
            strat+=messagebytes[i].length;
        }

        byte[] gk = engine0.AES_KeyGen();
        byte[] c0 = AESUtil.encryptAES(mbytes,gk);

        Element s = this.pairing.getZr().newRandomElement().getImmutable();
        Element t = this.pairing.getZr().newRandomElement().getImmutable();
        Element c1 = this.pairing.getGT().newElementFromBytes(gk).mul(this.pk.ehu.powZn(s)).getImmutable();
        Element c2 = this.pk.g.powZn(s).getImmutable();
        Element c3 = this.pk.g.powZn(t).getImmutable();
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
        Element[] v = new Element[arrayLength];

        for(int i=0;i<arrayLength;i++){
            v[i] = this.pairing.getZr().newRandomElement().getImmutable();
            e[i] = this.pk.u.powZn(v[i]).getImmutable();
            e1[i] = PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1).powZn(v[i])
                    .mul(PairingUtils.MapByteArrayToGroup(this.pairing,this.pk.ehu.powZn(t).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
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
        cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText CT = new cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText(Y,Z,c0,c1,c2,c3,cy,cz,e,e1,pID);
        //T
        Element[] T = new Element[arrayLength];
        Element[] T1 = new Element[arrayLength];
        Element[] T2 = new Element[arrayLength];

        for(int i=0;i<arrayLength;i++){
            Element x = this.pairing.getZr().newRandomElement().getImmutable();
            T[i] = this.ur.powZn(x).getImmutable();
            T1[i] = this.gu.powZn(v[i]).mul(this.gu.powZn(x)).mul(
                    PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1)
            ).getImmutable();
            T2[i] = PairingUtils.MapStringToGroup(this.pairing,id,PairingUtils.PairingGroupType.G1).powZn(v[i]).getImmutable();
        }

        return new CipherText(CT,T,T1,T2);
    }

}
