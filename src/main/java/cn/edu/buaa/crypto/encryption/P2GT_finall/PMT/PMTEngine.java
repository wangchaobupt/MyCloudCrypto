package cn.edu.buaa.crypto.encryption.P2GT_finall.PMT;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.P2GT_finall.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_finall.DecryptionKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.awt.image.BandCombineOp;
import java.util.Arrays;
import java.util.EventListener;
import java.util.Map;

public class PMTEngine {
    private static PMTEngine engine;
    private Pairing pairing;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    public static PMTEngine getInstance(){
        if(engine == null){
            engine = new PMTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing){
        this.pairing = pairing;
    }

    public Trapdoor_doctor DTrapdoorGen(CipherText ct, DecryptionKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());

        Element A = pairing.getGT().newOneElement().getImmutable();
        try{
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.Z, accessControlParameter);

            for(String j : omegaElementsMap.keySet()){
                Element d = sk.getD1().get(j);
                Element d1 = sk.getD2().get(j);
                Element cz = ct.Cz.get(j);
                Element lambda = omegaElementsMap.get(j);
                A = A.mul(this.pairing.pairing(ct.C3,d).div(this.pairing.pairing(cz,d1)).powZn(lambda)).getImmutable();
            }
        }catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }

        return new Trapdoor_doctor(A);
    }

    public Trapdoor_specialist STrapdoorGen(CipherText ct,DecryptionKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException {

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] rhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, rhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.Z, accessControlParameter);
        Element A = pairing.getGT().newOneElement().getImmutable();
        for(String j : omegaElementsMap.keySet()){
            Element d = sk.getD1().get(j);
            Element d1 = sk.getD2().get(j);
            Element cz = ct.Cz.get(j);
            Element lambda = omegaElementsMap.get(j);
            A = A.mul(this.pairing.pairing(ct.C3,d).div(this.pairing.pairing(cz,d1)).powZn(lambda)).getImmutable();
        }

        int len = ct.E1.length;
        Element[] td = new Element[len];
        for(int i=0;i<len;i++){
            td[i] = ct.E2[i].div(PairingUtils.MapByteArrayToGroup(this.pairing,A.toBytes(),PairingUtils.PairingGroupType.G1)).getImmutable();
        }
        return new Trapdoor_specialist(td);
    }

    public TestParameter Test(Trapdoor_specialist TDb, Trapdoor_doctor TDa, CipherText CTc, CipherText CTd){
        byte[][] pIDc = CTc.pID;
        byte[][] pIDd = CTd.pID;
        int[] rs = new int[pIDd.length];
        for(int i=0;i<pIDd.length;i++){
            rs[i] = 0;
        }

        for(int i=0;i<pIDc.length;i++){
            for(int j=0;j<pIDd.length;j++){
                if(Arrays.equals(pIDc[i],pIDd[j])){
//                    System.out.println(j);
                    Element Bc = CTc.E2[i].div(PairingUtils.MapByteArrayToGroup(this.pairing,TDa.getTD().toBytes(),PairingUtils.PairingGroupType.G1)).getImmutable();
//                    System.out.println("1:"+this.pairing.pairing(CTc.E1[i],TDb.getTD()[j]));
//                    System.out.println("2:"+this.pairing.pairing(CTd.E1[j],Bc));
                    if(this.pairing.pairing(CTc.E1[i],TDb.getTD()[j])
                            .isEqual(this.pairing.pairing(CTd.E1[j],Bc))){
                        rs[j] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs,pIDd);
    }
}

