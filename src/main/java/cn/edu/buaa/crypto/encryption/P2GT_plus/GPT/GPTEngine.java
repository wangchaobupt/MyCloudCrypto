package cn.edu.buaa.crypto.encryption.P2GT_plus.GPT;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.P2GT_plus.CipherText;
import cn.edu.buaa.crypto.encryption.P2GT_plus.DecryptionKey;
import cn.edu.buaa.crypto.encryption.P2GT_plus.P2GT_plusEngine;
import cn.edu.buaa.crypto.encryption.P2GT_plus.PublicKey;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Arrays;

public class GPTEngine {
    private static GPTEngine engine;
    private Pairing pairing;
    private PublicKey pk;
    private AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    public static GPTEngine getInstance(){
        if(engine == null){
            engine = new GPTEngine();
        }
        return engine;
    }

    public void init(Pairing pairing,PublicKey pk){
        this.pairing = pairing;
        this.pk = pk;
    }

    public Trapdoor TrapdoorGen(DecryptionKey ska, DecryptionKey skb, Element x,P2GT_plusEngine engine){
        Element U = this.pk.ur.powZn(x).getImmutable();
        Element G = this.pk.gu.powZn(x).getImmutable();
        Element ka = ska.getK().powZn(x).getImmutable();
        Element ka1 = ska.getK1().powZn(x).getImmutable();
        Element kb = skb.getK().powZn(x).getImmutable();
        Element kb1 = skb.getK1().powZn(x).getImmutable();

        return new Trapdoor(U,G,ka,ka1,kb,kb1);
    }

    public TestParameter Test(CipherText CTa, CipherText CTb, Trapdoor td){
        byte[][] pIDa = CTa.getCT().pID;
        byte[][] pIDb = CTb.getCT().pID;

//        System.out.println("pIDa:");
//        for(int i=0;i<pIDa.length;i++)  System.out.println(Arrays.toString(pIDa[i]));
//        System.out.println("pIDb:");
//        for(int i=0;i<pIDb.length;i++)  System.out.println(Arrays.toString(pIDb[i])) ;

        int[] rs = new int[pIDa.length];
        for(int i=0;i<pIDa.length;i++) rs[i] = 0;
        for(int i=0;i<pIDa.length;i++){
            for(int j=0;j<pIDb.length;j++){
                if(Arrays.equals(pIDa[i],pIDb[j])){
                    Element Ba = this.pairing.pairing(CTa.getCT().E1[i],td.getKa())
                            .div(this.pairing.pairing(CTa.getT2()[i],td.getKa1())).getImmutable();
                    Element Bb = this.pairing.pairing(CTb.getCT().E1[j],td.getKb())
                            .div(this.pairing.pairing(CTb.getT2()[j],td.getKb1())).getImmutable();

                    Element A = this.pairing.pairing(CTa.getT1()[i],td.getU())
                            .div(Ba.mul(this.pairing.pairing(CTa.getT()[i],td.getG()))).getImmutable();
                    Element B = this.pairing.pairing(CTb.getT1()[j],td.getU())
                            .div(Bb.mul(this.pairing.pairing(CTb.getT()[j],td.getG()))).getImmutable();
                    if(A.isEqual(B)){
                        rs[i] = 1;
                    }
                    break;
                }
            }
        }
        return new TestParameter(rs);
    }
}
