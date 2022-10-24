package cn.edu.buaa.crypto.encryption.LH_SPS;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class LH_SPSEngine {
    private static LH_SPSEngine engine;
    private Pairing pairing;
    private Element h;
    private int nmax;
    private int l = 10;

    private static LH_SPSEngine getInstance(){
        if(engine == null){
            engine = new LH_SPSEngine();
        }
        return engine;
    }

    public Element getHash(int[] tau,Element[] w){
        Element res = w[0];
        for(int i=1;i<=l;i++){
            if(tau[i] == 0) continue;
            res = res.mul(w[i]).getImmutable();
        }
        return res;
    }

    public AllKey KeyGen(Pairing pairing,Element h,int n){
        this.pairing = pairing;
        this.h = h;
        this.nmax = n;

        Element alpha_z = pairing.getZr().newRandomElement().getImmutable();
        Element alpha_r = pairing.getZr().newRandomElement().getImmutable();
        Element beta_z = pairing.getZr().newRandomElement().getImmutable();
        Element gz = h.powZn(alpha_z).getImmutable();
        Element gr = h.powZn(alpha_r).getImmutable();
        Element hz = h.powZn(beta_z).getImmutable();
        Element[] xi = new Element[n];
        Element[] gamma = new Element[n];
        Element[] delta = new Element[n];
        Element[] gi = new Element[n];
        Element[] hi = new Element[n];

        for(int i=0;i<n;i++){
            xi[i] = pairing.getZr().newRandomElement().getImmutable();
            gamma[i] = pairing.getZr().newRandomElement().getImmutable();
            delta[i] = pairing.getZr().newRandomElement().getImmutable();
            gi[i] = gz.powZn(xi[i]).mul(gr.powZn(gamma[i])).getImmutable();
            hi[i] = hz.powZn(xi[i]).mul(h.powZn(delta[i])).getImmutable();
        }

        Element[] w = new Element[l+1];
        for(int i=0;i<=l;i++){
            w[i] = pairing.getG1().newRandomElement().getImmutable();
        }
        PublicKey pk = new PublicKey(gz,gr,h,hz,gi,hi,w);
        SecretKey sk = new SecretKey(hz.powZn(alpha_r),xi,gamma,delta);
        return new AllKey(pk,sk);
    }

    public SignParameter Sign(PublicKey pk,SecretKey sk,int[] tau,Element[] M){
        Element[] xi = sk.xi;
        Element[] gamma = sk.gamma;
        Element[] delta = sk.delta;
        Element theta = pairing.getZr().newRandomElement().getImmutable();
        Element rho = pairing.getZr().newRandomElement().getImmutable();

        Element Z = pk.gr.powZn(theta).getImmutable();
        Element R = pk.gz.powZn(theta.negate()).getImmutable();
        Element U = sk.hz_alpha.powZn(theta.negate()).getImmutable();
        Element V = pk.h.powZn(rho).getImmutable();
        for(int i=0;i<M.length;i++){
            Z = Z.mul(M[i].powZn(xi[i].negate())).getImmutable();
            R = R.mul(M[i].powZn(gamma[i].negate())).getImmutable();
            U = U.mul(M[i].powZn(delta[i].negate())).getImmutable();
        }
        U = U.mul(getHash(tau,pk.w).powZn(rho.negate())).getImmutable();
        return new SignParameter(Z,R,U,V);
    }

    public boolean Verify(PublicKey pk,SignParameter sign,int[] tau,Element[] M){
        Element[] gi = pk.gi;
        Element[] hi = pk.hi;
        Element gM = pairing.getGT().newOneElement().getImmutable();
        Element hM = pairing.getGT().newOneElement().getImmutable();

        for(int i=0;i<M.length;i++){
            gM = gM.mul(pairing.pairing(gi[i],M[i])).getImmutable();
            hM = hM.mul(pairing.pairing(hi[i],M[i])).getImmutable();
        }

        if(pairing.pairing(pk.gz,sign.Z).mul(pairing.pairing(pk.gr,sign.R)).mul(gM)
                .equals(pairing.getGT().newOneElement())
        && pairing.pairing(pk.hz,sign.Z).mul(pairing.pairing(pk.h,sign.U))
                .mul(pairing.pairing(getHash(tau,pk.w), sign.V)).mul(hM)
                .equals(pairing.getGT().newOneElement())){
            return true;
        }
        return false;
    }

    public boolean Veriy_first(PublicKey pk,SignParameter sign,Element[] M){
        Element[] gi = pk.gi;
        Element gM = pairing.getGT().newOneElement().getImmutable();

        for(int i=0;i<M.length;i++){
            gM = gM.mul(pairing.pairing(gi[i],M[i])).getImmutable();
        }

        if(pairing.pairing(pk.gz,sign.Z).mul(pairing.pairing(pk.gr,sign.R)).mul(gM)
                .equals(pairing.getGT().newOneElement())){
            return true;
        }
        return false;
    }
}
