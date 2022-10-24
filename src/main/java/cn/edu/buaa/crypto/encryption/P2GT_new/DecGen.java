package cn.edu.buaa.crypto.encryption.P2GT_new;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Arrays;
import java.util.Map;

public class DecGen {
    private Pairing pairing;
    private LSSSLW10Engine accessControlEngine;

    public void init(Pairing pairing) {
        this.pairing = pairing;
        this.accessControlEngine = LSSSLW10Engine.getInstance();
    }

    public Element[] generaterDec(CipherText ct, DecryptionKey sk, String[] attributes) throws Exception {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] stringRhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributes, accessControlParameter);

        Element B = pairing.getGT().newOneElement().getImmutable();
        for (String attribute : omegaElementsMap.keySet()) {
            Element C2 = ct.C2;
            Element D0 = sk.getD0().get(attribute);
            Element Cs0 = ct.Cs0.get(attribute);
            Element D1 = sk.getD1().get(attribute);
            Element Cs1 = ct.Cs1.get(attribute);
            Element D2 = sk.getD2().get(attribute);
            Element lambda = omegaElementsMap.get(attribute);
            B = B.mul(pairing.pairing(C2, D0).mul(pairing.pairing(Cs0, D1)).mul(pairing.pairing(Cs1, D2)).powZn(lambda)).getImmutable();
        }

        Element ek1 = ct.C1.div(B).getImmutable();
        byte[] d = ek1.toBytes();
        byte[] ek = new byte[16];
        int len = 0;
        for(int i=0;i<d.length;i++){
            if(d[i]!=0){
                ek[len++] = d[i];
            }
            if(len==16) break;
        }

        byte[] mbytes = AESUtil.decryptAES(ct.C0,ek);
        //System.out.println("mbyte:"+ Arrays.toString(mbytes));
        //System.out.println("mlen:"+mbytes.length);

        //切割
        int splitLength = 128;
        int arrayLength = (int) Math.ceil(mbytes.length / splitLength);

        //System.out.println("arrayLength:"+arrayLength);
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
            m[i] = pairing.getGT().newElementFromBytes(n[i]);
        }
        return m;
    }
}
