package cn.edu.buaa.crypto.encryption.P2GT_plus_new.GPT;

import cn.edu.buaa.crypto.encryption.GT.ELGamal;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.PublicKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Arrays;

public class GPTEngine {
    private static GPTEngine engine;
    private Pairing pairing;
    public PublicKey pk;

    public static GPTEngine getInstance(){
        if(engine == null){
            engine = new GPTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing, PublicKey pk){
        this.pairing = pairing;
        this.pk = pk;
    }

    public Trapdoor TrapdoorGen(DecryptionKey sk, Element x){
        return new Trapdoor(sk.getK().mul(x).getImmutable(),sk.getK1());
    }

    public TestParameter Test(CipherText CTa, CipherText CTb, Trapdoor TDa, Trapdoor TDb){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDb = CTb.getCT().pID;
        int[] rs = new int[pIDa.length];
        for(int i=0;i<pIDa.length;i++) rs[i] = 0;

        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDb.length;j++){
                if(Arrays.equals(pIDa[i],pIDb[j])){
                    Element Ba = CTa.getT()[i].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,
                                    this.pairing.pairing(TDa.getTD1(),CTa.getCT().Ei1[i]).getImmutable().toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();
                    Element Bb = CTb.getT()[i].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,
                                    this.pairing.pairing(TDb.getTD1(),CTb.getCT().Ei1[j]).getImmutable().toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();

                    if(this.pairing.pairing(Ba.powZn(TDa.getTD0()),CTb.getT1()[j])
                            .isEqual(this.pairing.pairing(Bb.powZn(TDb.getTD0()),CTa.getT1()[i]))){
                        rs[i] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs);
    }
}
