package cn.edu.buaa.crypto.encryption.P2GT_plus.GCT;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;


import cn.edu.buaa.crypto.encryption.P2GT_plus.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Arrays;


public class GCTEngine {
    private static GCTEngine engine;
    private Pairing pairing;
    private PublicKey pk;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
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

    public Trapdoor TrapdoorGen(CipherText ct, DecryptionKey sk){
        Element[] k1 = new Element[ct.getT1().length];
        for(int i=0;i<ct.getT1().length;i++){
            k1[i] = this.pairing.pairing(ct.getT2()[i],sk.getK1());
        }

        return new Trapdoor(sk.getK(),k1);
    }

    public TestParameter Test(Trapdoor TDa, Trapdoor TDb, CipherText CTa, CipherText CTb){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDb = CTb.getCT().pID;
        int[] rs = new int[pIDa.length];
        for(int i=0;i<rs.length;i++) rs[i] = 0;

        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDb.length;j++){
                if(Arrays.equals(pIDa[i],pIDb[j])) {
                    Element Ba = this.pairing.pairing(CTa.getCT().E1[i],TDa.getK()).div(TDa.getK1()[i]).getImmutable();
                    Element Bb = this.pairing.pairing(CTb.getCT().E1[j],TDb.getK()).div(TDb.getK1()[j]).getImmutable();

                    Element A = this.pairing.pairing(CTa.getT1()[i],this.pk.ur).div(
                            Ba.mul(this.pairing.pairing(CTa.getT()[i],this.pk.gu))
                    ).getImmutable();
                    Element B = this.pairing.pairing(CTb.getT1()[j],this.pk.ur).div(
                            Bb.mul(this.pairing.pairing(CTb.getT()[j],this.pk.gu))
                    ).getImmutable();
                    if(A.isEqual(B)){
                        rs[j] = 1;
                    }
                    break;
                }
            }
        }

        return new TestParameter(rs,pIDa);
    }

}
