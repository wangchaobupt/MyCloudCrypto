package cn.edu.buaa.crypto.encryption.P2GT_new.PMT;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.P2GT_new.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

public class STrapGen {
    private Pairing pairing;
    private LSSSLW10Engine accessControlEngine;

    public void init(Pairing pairing) {
        this.pairing = pairing;
        this.accessControlEngine = LSSSLW10Engine.getInstance();
    }

    public Trapdoor_specialist generateSTrapdoor(CipherText ct, DecryptionKey sk) throws PolicySyntaxException, InvalidCipherTextException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(sk.getAccessPolicy());
        String[] stringRhos = ParserUtils.GenerateRhos(sk.getAccessPolicy());


        Element B = pairing.getGT().newOneElement().getImmutable();
        try{
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, ct.Z, accessControlParameter);
            for (String attribute : omegaElementsMap.keySet()) {
                Element E0 = ct.E0;
                Element D0 = sk.getD0().get(attribute);
                Element Es0 = ct.Es0.get(attribute);
                Element D1 = sk.getD1().get(attribute);
                Element Es1 = ct.Es1.get(attribute);
                Element D2 = sk.getD2().get(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                B = B.mul(pairing.pairing(E0, D0).mul(pairing.pairing(Es0, D1)).mul(pairing.pairing(Es1, D2)).powZn(lambda)).getImmutable();
            }
        }catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }

        int len = ct.Ei0.length;
        Element[] td = new Element[len];
        for (int i = 0; i < len; i++) {
            td[i] = ct.Ei0[i].div(PairingUtils.MapByteArrayToGroup(this.pairing, B.toBytes(), PairingUtils.PairingGroupType.G1)).getImmutable();
        }
        return new Trapdoor_specialist(td);
    }
}
