package cn.edu.buaa.crypto.encryption.P2GT_plus_new.DST;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;

import cn.edu.buaa.crypto.encryption.P2GT_plus_new.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus_new.PublicKey;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.sql.SQLSyntaxErrorException;
import java.util.Arrays;

public class DSTEngine {
    private static DSTEngine engine;
    private Pairing pairing;
    public PublicKey pk;
    private AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
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

    public Trapdoor_patient PTrapdoorGen(DecryptionKey sk, Element x){
        Element td0 = sk.getK().mul(x).getImmutable();
        return new Trapdoor_patient(td0,sk.getK1());
    }

    public Trapdoor_sepcialist STrapdoorGen(DecryptionKey sk, CipherText ct, Element x){
        Element td0 = sk.getK().mul(x).getImmutable();
        Element[] td1 = new Element[ct.getCT().Ei1.length];
        for(int i=0;i<ct.getCT().Ei1.length;i++){
            td1[i] = this.pairing.pairing(ct.getCT().Ei1[i],sk.getK1()).getImmutable();
        }
        return new Trapdoor_sepcialist(td0,td1);
    }

    public TestParameter Test(Trapdoor_sepcialist TDm, Trapdoor_patient TDa, CipherText CTm, CipherText CTa){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDm = CTm.getCT().pID;
        int[] rs = new int[pIDm.length];
        for(int i=0;i<rs.length;i++) rs[i] = 0;

        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDm.length;j++){
                if(Arrays.equals(pIDa[i],pIDm[j])){
                    Element H =  this.pairing.pairing(TDa.getTD1(),CTa.getCT().Ei1[i]).getImmutable();
                    Element Ba = CTa.getT()[i].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,H.toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();
                    Element Bm = CTm.getT()[j].div(
                            PairingUtils.MapByteArrayToGroup(this.pairing,TDm.getTD1()[j].toBytes(),PairingUtils.PairingGroupType.G1)
                    ).getImmutable();

                    Element A = this.pairing.pairing(Ba.powZn(TDa.getTD0()),CTm.getT1()[j]).getImmutable();
                    Element B = this.pairing.pairing(Bm.powZn(TDm.getTD0()),CTa.getT1()[i]).getImmutable();
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
