package cn.edu.buaa.crypto.encryption.P2GT_new;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

public class SKGen {
    private Pairing pairing;
    private LSSSLW10Engine accessControlEngine;

    public void init(Pairing pairing) {
        this.pairing = pairing;
        this.accessControlEngine = LSSSLW10Engine.getInstance();
    }

    public DecryptionKey generateSK(String accessPolicy,MasterSecretKey msk,PublicKey pk) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);

        Map<String, Element> D0 = new HashMap<String, Element>();
        Map<String, Element> D1 = new HashMap<String, Element>();
        Map<String, Element> D2 = new HashMap<String, Element>();

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, msk.getA(), accessControlParameter);
        for (String rho : lambdaElementsMap.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            System.out.println("rho:"+rho);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            Element d0 = pk.g.powZn(lambdaElementsMap.get(rho)).mul(pk.w.powZn(ti)).getImmutable();
            D0.put(rho, d0);
            Element d1 = pk.u.powZn(elementRho).mul(pk.h).powZn(ti.negate()).getImmutable();
            D1.put(rho, d1);
            Element d2 = pk.g.powZn(ti).getImmutable();
            D2.put(rho, d2);
        }
        return new DecryptionKey(accessPolicy,D0,D1,D2);
    }
}
