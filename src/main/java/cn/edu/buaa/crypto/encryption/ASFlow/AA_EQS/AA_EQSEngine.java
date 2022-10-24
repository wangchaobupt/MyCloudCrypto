package cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

public class AA_EQSEngine {
    private static AA_EQSEngine engine;
    private Pairing pairing;
    private String[] U;
    private Element h,g;
    public static AA_EQSEngine getInstance(){
        if(engine == null){
            engine = new AA_EQSEngine();
        }
        return engine;
    }

    public AllKey Setup(Pairing pairing,String[] U,Element g,Element h){
        this.U = U;
        this.pairing = pairing;
        this.g = g;
        this.h = h;
        Map<String, Element> zx = new HashMap<>();
        Map<String, Element> Zx = new HashMap<>();
        for(String att : U){
            Element zi = pairing.getZr().newRandomElement().getImmutable();
            zx.put(att,zi);
            Zx.put(att,h.powZn(zi).getImmutable());
        }
        SecretKey esk = new SecretKey(zx);
        PublicKey evk = new PublicKey(Zx);
        return new AllKey(esk,evk);
    }

    public SecretKey KeyGen(SecretKey esk,String[] S){
        Map<String, Element> res = new HashMap<>();
        Map<String, Element> zx = esk.zx;
        for(String att : S){
            res.put(att,zx.get(att));
        }
        return new SecretKey(res);
    }

    public Signature Sign(SecretKey sk,Map<String,Element> M,Element tau){
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element y1 = y.invert().getImmutable();
        Element Y1 = g.powZn(y1).getImmutable();
        Element Y2 = h.powZn(y1).getImmutable();
        Element Y3 = PairingUtils.MapByteArrayToGroup(pairing,tau.toBytes(),PairingUtils.PairingGroupType.G2).powZn(y1).getImmutable();
        Element Y0 = pairing.getG1().newOneElement().getImmutable();
        for(String att : M.keySet()){
            Y0 = Y0.mul(M.get(att).powZn(sk.zx.get(att)));
        }
        Y0 = Y0.powZn(y).getImmutable();
        return new Signature(Y0,Y1,Y2,Y3);
    }

    public boolean Verify(PublicKey evk,Map<String,Element> M,Element tau,Signature sign){
        Element Htau = PairingUtils.MapByteArrayToGroup(pairing,tau.toBytes(),PairingUtils.PairingGroupType.G2).getImmutable();
        if(pairing.pairing(sign.Y1,h).equals(pairing.pairing(g,sign.Y2))
        && pairing.pairing(sign.Y1,Htau).equals(pairing.pairing(g,sign.Y3))){
            Element A = pairing.getGT().newOneElement().getImmutable();
            for(String att : M.keySet()){
                A = A.mul(pairing.pairing(M.get(att),evk.Zx.get(att))).getImmutable();
            }
            if(A.equals(pairing.pairing(sign.Y0,sign.Y2))){
                return true;
            }
        }
        return false;
    }

}
