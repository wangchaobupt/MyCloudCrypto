package cn.edu.buaa.crypto.encryption.P2GT_new.PMT;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.encryption.P2GT_new.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_new.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_new.P2GTEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.util.Arrays;
import java.util.Map;

public class PMTEngine {
    private static PMTEngine engine;
    private static P2GTEngine engine0;
    private Pairing pairing;
    private AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();

    public static PMTEngine getInstance() {
        if (engine == null) {
            engine = new PMTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing,P2GTEngine engine) {
        this.pairing = pairing;
        this.engine0 = engine;
    }

    public Trapdoor_doctor DTrapdoorGen(CipherText ct, DecryptionKey sk) throws Exception {
        DTrapGen dTrapGen = new DTrapGen();
        dTrapGen.init(this.pairing);
        return dTrapGen.generateDTrapdoor(ct,sk);
    }

    public Trapdoor_specialist STrapdoorGen(CipherText ct, DecryptionKey sk) throws PolicySyntaxException, UnsatisfiedAccessControlException, InvalidCipherTextException {
        STrapGen sTrapGen = new STrapGen();
        sTrapGen.init(this.pairing);
        return sTrapGen.generateSTrapdoor(ct,sk);
    }

    public TestParameter Test(Trapdoor_specialist TDb, Trapdoor_doctor TDa, CipherText CTc, CipherText CTd){
        byte[][] pIDc = CTc.pID;
        byte[][] pIDd = CTd.pID;
        int[] rs = new int[pIDd.length];
        for (int i = 0; i < pIDd.length; i++) {
            rs[i] = 0;
        }

        for (int i = 0; i < pIDc.length; i++) {
            for (int j = 0; j < pIDd.length; j++) {
                if (Arrays.equals(pIDc[i], pIDd[j])) {
                    Element Hc = CTc.Ei0[i].div(PairingUtils.MapByteArrayToGroup(this.pairing, TDa.getTD().toBytes(), PairingUtils.PairingGroupType.G1)).getImmutable();
                    if (this.pairing.pairing(CTc.Ei1[i], TDb.getTD()[j])
                            .isEqual(this.pairing.pairing(CTd.Ei1[i], Hc))) {
                        rs[j] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs,pIDd);
    }
}
