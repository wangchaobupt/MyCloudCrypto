package cn.edu.buaa.crypto.encryption.P2GT_plus_new.GCT;

import cn.edu.buaa.crypto.encryption.P2GT_plus_new.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.PublicKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.text.CharacterIterator;
import java.util.Arrays;

public class GCTEngine {
    private static GCTEngine engine;
    private Pairing pairing;
    private PublicKey pk;
    public static GCTEngine getInstance(){
        if(engine == null){
            engine = new GCTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing, PublicKey pk){
        this.pairing = pairing;
        this.pk = pk;
    }

    public Trapdoor TrapdoorGen(CipherText ct, DecryptionKey sk, Element x){
        Element[] tdk = new Element[ct.getCT().Ei1.length];
        for(int i=0;i<ct.getCT().Ei1.length;i++){
            tdk[i] = this.pairing.pairing(sk.getK1(),ct.getCT().Ei1[i]).getImmutable();
        }
        return new Trapdoor(sk.getK().mul(x).getImmutable(),tdk);
    }

    public TestParameter Test(Trapdoor TDa,Trapdoor TDb,CipherText CTa,CipherText CTb){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDb = CTb.getCT().pID;
        int[] rs = new int[pIDa.length];
        for(int i=0;i<rs.length;i++) rs[i] = 0;

        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDb.length;j++){
                if(Arrays.equals(pIDa[i],pIDb[j])) {
                    Element Ba = CTa.getT()[i].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,TDa.getTDk()[i].toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();
                    Element Bb = CTb.getT()[j].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,TDb.getTDk()[j].toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();

                    if(this.pairing.pairing(Ba.powZn(TDa.getTD()),CTb.getT1()[j])
                            .isEqual(this.pairing.pairing(Bb.powZn(TDb.getTD()),CTa.getT1()[i]))){
                        rs[j] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs,pIDa);
    }
}
