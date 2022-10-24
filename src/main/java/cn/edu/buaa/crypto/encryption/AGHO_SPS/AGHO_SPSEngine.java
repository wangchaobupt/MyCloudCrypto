package cn.edu.buaa.crypto.encryption.AGHO_SPS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class AGHO_SPSEngine {
    private static AGHO_SPSEngine engine;
    public int tMax;
    public Element g,h;
    public Pairing pairing;
    public static AGHO_SPSEngine getInstance(){
        if(engine == null){
            engine = new AGHO_SPSEngine();
        }
        return engine;
    }

    public AllKey KeyGen(int max,Pairing pairing,Element g,Element h){
        this.pairing = pairing;
        tMax = max;
        this.h = h;
        this.g = g;
//        h = pairing.getG2().newRandomElement().getImmutable();
//        g = pairing.getG1().newRandomElement().getImmutable();
        Element[] u = new Element[tMax];
        Element v = pairing.getZr().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();
        Element[] U = new Element[tMax];
        Element V = h.powZn(v).getImmutable();
        Element Z = h.powZn(z).getImmutable();
        for(int i=0;i<tMax;i++){
            u[i] = pairing.getZr().newRandomElement().getImmutable();
            U[i] = h.powZn(u[i]).getImmutable();
        }
        SigningKey sk = new SigningKey(u,v,z);
        VerificationKey vk = new VerificationKey(U,V,Z);
        return new AllKey(sk,vk);
    }

    public Signature Sign(SigningKey sk,Element[] M){
        Element[] u = sk.u;
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element R = g.powZn(r).getImmutable();
        Element W = g.powZn(sk.z.sub(r.mul(sk.v))).getImmutable();
        int k = M.length;
        for(int i=0;i<k;i++){
            W = W.mul(M[i].powZn(u[i].negate())).getImmutable();
        }
        Element T = h.powZn(r.invert()).getImmutable();
        return new Signature(R,W,T);
    }

    public boolean Verify(VerificationKey vk,Element[] M,Signature sign){
        int k = M.length;
        Element[] U = vk.U;
        Element mU = pairing.getGT().newOneElement().getImmutable();
        for(int i=0;i<k;i++){
            mU = mU.mul(pairing.pairing(M[i],U[i])).getImmutable();
        }
        if(pairing.pairing(sign.R,vk.V).mul(pairing.pairing(sign.W,h)).mul(mU).equals( pairing.pairing(g,vk.Z))){
            if(pairing.pairing(sign.R,sign.T).equals( pairing.pairing(g,h))){
                return true;
            }
        }
        return false;
    }
}
