package cn.edu.buaa.crypto.encryption.P2GT_plus.DST;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;

import cn.edu.buaa.crypto.encryption.P2GT_plus.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus.P2GT_plusEngine;
import cn.edu.buaa.crypto.encryption.P2GT_plus.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Arrays;

public class DSTEngine {
    private static DSTEngine engine;
    private Pairing pairing;
    private PublicKey pk;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    public static DSTEngine getInstance(){
        if(engine == null){
            engine = new DSTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing, PublicKey pk){
        this.pairing = pairing;
        this.pk = pk;
    }

    public Trapdoor_patient PTrapdoorGen(DecryptionKey sk,Element x){
        Element k = sk.getK().powZn(x).getImmutable();
        Element k1 = sk.getK1().powZn(x).getImmutable();
        return new Trapdoor_patient(k,k1);
    }

    public Trapdoor_sepcialist STrapdoorGen(DecryptionKey sk, CipherText ct,Element x){
        Element K = sk.getK().powZn(x).getImmutable();
        Element[] k1 = new Element[ct.getT2().length];
        for(int i=0;i<ct.getT2().length;i++){
            k1[i] = this.pairing.pairing(ct.getT2()[i],sk.getK1().powZn(x)).getImmutable();
        }
        return new Trapdoor_sepcialist(K,k1);
    }

    public TestParameter Test(Trapdoor_sepcialist TDm, Trapdoor_patient TDa, CipherText CTm, CipherText CTa,Element U,Element G){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDm = CTm.getCT().pID;
        int[] rs = new int[pIDm.length];
        for(int i=0;i<rs.length;i++) rs[i] = 0;

        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDm.length;j++){
                if(Arrays.equals(pIDa[i],pIDm[j])){
                    Element Ba = this.pairing.pairing(CTa.getCT().E1[i],TDa.getK()).div(
                            this.pairing.pairing(CTa.getT2()[i],TDa.getK1())
                    ).getImmutable();
                    Element Bm = this.pairing.pairing(CTm.getCT().E1[j],TDm.getK()).div(TDm.getK1()[j]).getImmutable();

                    Element A = this.pairing.pairing(CTa.getT1()[i],U).div(
                            Ba.mul(this.pairing.pairing(CTa.getT()[i],G))
                    ).getImmutable();
                    Element B = this.pairing.pairing(CTm.getT1()[j],U).div(
                            Bm.mul(this.pairing.pairing(CTm.getT()[j],G))
                    ).getImmutable();
                    if(A.isEqual(B)){
                        rs[j] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs,pIDm);
    }


}
