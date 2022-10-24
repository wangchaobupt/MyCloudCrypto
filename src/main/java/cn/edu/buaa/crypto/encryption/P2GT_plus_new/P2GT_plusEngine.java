package cn.edu.buaa.crypto.encryption.P2GT_plus_new;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.P2GT_finall.AESUtil;
import cn.edu.buaa.crypto.encryption.P2GT_new.P2GTEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class P2GT_plusEngine {
    private static P2GT_plusEngine engine;
    private static P2GTEngine engine0;
    private Pairing pairing;
    private PublicKey PK;
    private cn.edu.buaa.crypto.encryption.P2GT_new.PublicKey pk;
    private Element gr;

    private AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
    public static P2GT_plusEngine getInstance(){
        if(engine == null){
            engine = new P2GT_plusEngine();
        }
        return engine;
    }
    public Pairing getPairing() {return this.pairing;}

    public MasterSecretKey Setup(String perperties){
        this.engine0 = new P2GTEngine();
        cn.edu.buaa.crypto.encryption.P2GT_new.MasterSecretKey msk = engine0.Setup(perperties);
        this.pk = engine0.getPk();
        this.pairing = engine0.getPairing();
        Element r = this.pairing.getZr().newRandomElement().getImmutable();
        this.gr = this.pk.g.powZn(r).getImmutable();
        this.PK = new PublicKey(pk,this.gr);
        return new MasterSecretKey(msk,r);
    }

    public PublicKey getPK(){return this.PK;}

    public DecryptionKey KeyGen(String accessPolicy, MasterSecretKey msk,String id) throws PolicySyntaxException {
        cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey SK = engine0.KeyGen(accessPolicy,msk.getMK());
        Element u = this.pairing.getZr().newRandomElement().getImmutable();
        Element k1 = PairingUtils.MapStringToGroup(this.pairing,id,PairingUtils.PairingGroupType.G1).powZn(msk.getR()).getImmutable();
        return new DecryptionKey(SK,u,k1);
    }

    public byte[] AES_KeyGen() throws Exception {
        //初始AES密钥
        byte[] bytes = this.pairing.getGT().newRandomElement().getImmutable().toBytes();
        Element element = pairing.getZr().newElement().setFromHash(bytes,0,bytes.length);
        byte[] aeskey = AESUtil.initKey(new SecureRandom(element.toBytes()));
        return aeskey;
    }

    public CipherText Encrypt(String[] Y,String[] Z,String id,Element[] message,byte[] kmc, DecryptionKey dk) throws Exception {
        //CT
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
        byte[] ek = AES_KeyGen();
        byte[] C0 = cn.edu.buaa.crypto.encryption.P2GT_new.AESUtil.encryptAES(mbytes,ek);

        Element s = this.pairing.getZr().newRandomElement().getImmutable();
        Element C1 = this.pairing.getGT().newElementFromBytes(ek).mul(pk.ega.powZn(s)).getImmutable();
        Element C2 = pk.g.powZn(s).getImmutable();

        Map<String, Element> Cs0 = new HashMap<String, Element>();
        Map<String, Element> Cs1 = new HashMap<String, Element>();

        for (String attribute : Y) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element c1 = pk.g.powZn(ri).getImmutable();
            Cs0.put(attribute, c1);
            Element c2 = pk.u.powZn(elementAttribute).mul(pk.h).powZn(ri)
                    .mul(pk.w.powZn(s.negate())).getImmutable();
            Cs1.put(attribute, c2);
        }

        Element t = this.pairing.getZr().newRandomElement().getImmutable();
        Element E0 = pk.g.powZn(t).getImmutable();
        int arrayLength = message.length;
        byte[][] n = messagebytes;

        Element[] Ei0 = new Element[arrayLength];
        Element[] Ei1 = new Element[arrayLength];
        byte[][] pID = new byte[arrayLength][];

        Element[] v = new Element[arrayLength];
        for(int i=0;i<arrayLength;i++){
            v[i] = this.pairing.getZr().newRandomElement().getImmutable();
            Ei1[i] = pk.g.powZn(v[i]).getImmutable();
            Ei0[i] = PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1).powZn(v[i])
                    .mul(PairingUtils.MapByteArrayToGroup(this.pairing,pk.ega.powZn(t).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
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
            pID[i] = cn.edu.buaa.crypto.encryption.P2GT_finall.AESUtil.encryptAES(data,kmc);
        }

        Map<String, Element> Es0 = new HashMap<String, Element>();
        Map<String, Element> Es1 = new HashMap<String, Element>();

        for (String attribute : Z) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element zi = pairing.getZr().newRandomElement().getImmutable();
            Element e1 = pk.g.powZn(zi).getImmutable();
            Es0.put(attribute, e1);
            Element e2 = pk.u.powZn(elementAttribute).mul(pk.h).powZn(zi)
                    .mul(pk.w.powZn(t.negate())).getImmutable();
            Es1.put(attribute, e2);
        }

        cn.edu.buaa.crypto.encryption.P2GT_new.CipherText CT = new cn.edu.buaa.crypto.encryption.P2GT_new.CipherText(Y,Z,C0,C1,C2,Cs0,Cs1,E0,Ei0,Ei1,Es0,Es1,pID);
        //T
        Element[] T = new Element[arrayLength];
        Element[] T1 = new Element[arrayLength];

        for(int i=0;i<arrayLength;i++){
            Element x = this.pairing.getZr().newRandomElement().getImmutable();
            T1[i] = this.pk.g.powZn(dk.getK()).powZn(x).getImmutable();
            Element H2 = this.pairing.pairing(PairingUtils.MapStringToGroup(this.pairing,id,PairingUtils.PairingGroupType.G1),this.gr).powZn(v[i]).getImmutable();
            T[i] = PairingUtils.MapByteArrayToGroup(this.pairing,n[i],PairingUtils.PairingGroupType.G1).powZn(x)
                    .mul(PairingUtils.MapByteArrayToGroup(this.pairing,H2.toBytes(),PairingUtils.PairingGroupType.G1)).getImmutable();
        }

        return new CipherText(CT,T,T1);
    }
}
