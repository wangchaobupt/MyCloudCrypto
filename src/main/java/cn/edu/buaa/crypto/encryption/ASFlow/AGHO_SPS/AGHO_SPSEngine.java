package cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class AGHO_SPSEngine {
    private static AGHO_SPSEngine engine;
    public Element g,h;
    public Pairing pairing;
    public int Max;
    public static AGHO_SPSEngine getInstance(){
        if(engine==null){
            engine = new AGHO_SPSEngine();
        }
        return engine;
    }

    public byte[] getBytes(String[] tau){
        int size = tau.length;
        byte[][] CTbytes = new byte[size][];
        int len = 0;
        for(int i=0;i<size;i++){
            CTbytes[i] = tau[i].getBytes();
            len += CTbytes[i].length;
        }
        byte[] res = new byte[len];
        int strat = 0;
        for(int i=0;i<size;i++){
            System.arraycopy(CTbytes[i],0,res,strat,CTbytes[i].length);
            strat+=CTbytes[i].length;
        }
        return res;
    }

    public AllKey Setup(int max,Pairing pairing,Element g,Element h){
        this.pairing = pairing;
        this.g = g;
        this.h = h;
        this.Max = max;
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element V = h.powZn(beta).getImmutable();
        Element W = h.powZn(gamma).getImmutable();
        Element[] z = new Element[max];
        Element[] U = new Element[max];
        for(int i=0;i<max;i++){
            z[i] = pairing.getZr().newRandomElement().getImmutable();
            U[i] = h.powZn(z[i]).getImmutable();
        }
        SigningKey ssk = new SigningKey(beta,gamma,z);
        VerficationKey svk = new VerficationKey(V,W,U);
        return new AllKey(svk,ssk);
    }

    public Signature Sign(SigningKey ssk,Element[] M,String[] tau){
        int k = M.length;
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element X0 = g.powZn(ssk.gamma.sub(ssk.beta.mul(r))).getImmutable();
        for(int i=0;i<k;i++){
            X0 = X0.mul(M[i].powZn(ssk.z[i].negate())).getImmutable();
        }
        Element X1 = g.powZn(r).getImmutable();
        Element X2 = h.powZn(r.invert()).getImmutable();
        Element X3 = PairingUtils.MapByteArrayToGroup(pairing,getBytes(tau),PairingUtils.PairingGroupType.G2).powZn(r).getImmutable();
        return new Signature(X0,X1,X2,X3);
    }

    public boolean Verify(VerficationKey svk,Element[] M,Element tau,Signature sign){
        Element Htau = PairingUtils.MapByteArrayToGroup(pairing,tau.toBytes(),PairingUtils.PairingGroupType.G2).getImmutable();
        int k = M.length;
        if(pairing.pairing(sign.X1,sign.X2).equals(pairing.pairing(g,h))
        && pairing.pairing(sign.X1,Htau).equals(pairing.pairing(g,sign.X3))){
            Element A = pairing.pairing(sign.X0,h).mul(
                    pairing.pairing(sign.X1,svk.V)
            );
            for(int i=0;i<k;i++){
                A = A.mul(pairing.pairing(M[i],svk.U[i])).getImmutable();
            }
            if(A.equals(pairing.pairing(g,svk.W))){
                return true;
            }
        }
        return false;
    }
}
