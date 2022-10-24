package cn.edu.buaa.crypto.encryption.ASFlow.TABS;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.algorithms.LagrangePolynomial;
import cn.edu.buaa.crypto.utils.PairingUtils;
import edu.princeton.cs.algs4.In;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.PortableInterceptor.INACTIVE;

import java.util.HashMap;
import java.util.Map;

public class TABSEngine {
    private static TABSEngine engine;
    private LagrangePolynomial lagrangePolynomial;
    private Pairing pairing;
    public PublicKey avk;
    private String[] U;
    private Element g,g0,h1,h2;
    private Map<String,Element> Zx;

    public static TABSEngine getInstance(){
        if(engine == null){
            engine = new TABSEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public byte[] getHbytes(Element msg,String[] B){
        int size = 1+B.length;
        byte[][] Wbytes = new byte[size][];
        Wbytes[0] = msg.toBytes();
        int len = Wbytes[0].length;
        int idx = 1;
        for(int i=0;i<B.length;i++){
            Wbytes[idx] = B[i].getBytes();
            len += Wbytes[idx].length;
            idx++;
        }
        byte[] res = new byte[len];
        int strat = 0;
        for(int i=0;i<size;i++){
            System.arraycopy(Wbytes[i],0,res,strat,Wbytes[i].length);
            strat+=Wbytes[i].length;
        }
        return res;
    }

    public MasterSecretKey Setup(String perperties,String[] U){
        pairing = PairingFactory.getPairing(perperties);
        this.U = U;
        g = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG2().newRandomElement().getImmutable();
        Element d0 = pairing.getZr().newRandomElement().getImmutable();
        Element d1 = pairing.getZr().newRandomElement().getImmutable();
        Element d2 = pairing.getZr().newRandomElement().getImmutable();
        g0 = g.powZn(d0).getImmutable();
        h1 = h.powZn(d2.sub(d1)).getImmutable();
        h2 = h.powZn(d2).getImmutable();
        Zx = new HashMap<>();
        Map<String,Element> zx = new HashMap<>();
        for(String att : U){
            Element value = pairing.getZr().newRandomElement().getImmutable();
            zx.put(att,value);
            Zx.put(att,g.powZn(value).getImmutable());
        }
        avk = new PublicKey(g,g0,h1,h2,Zx);
        return new MasterSecretKey(d0,d1,d2,zx);
    }

    public SignKey KeyGen(MasterSecretKey ask,String[] T,int t){
        lagrangePolynomial = new LagrangePolynomial(pairing,t-1,ask.d0);
        Map<String,Element> Dx = new HashMap<>();
        Map<String,Element> zx = ask.zx;
        for(String att : T){
            int x = Integer.valueOf(att);
            Dx.put(att,h2.powZn(lagrangePolynomial.evaluate(pairing.getZr().newElement(x)))
                    .mul(h1.powZn(zx.get(att))).getImmutable());
        }
        return new SignKey(Dx);
    }

    public SignParameter Sign(SignKey ak,Element m,String[] B){
        int len = B.length;
        int[] attributes = new int[len];
        for(int i=0;i<len;i++){
            attributes[i] = Integer.parseInt(B[i]);
        }
        Map<String,Element> Dx = ak.Dx;
        Element S1 = pairing.getG1().newRandomElement().getImmutable();
        Element S2 = pairing.getG1().newRandomElement().getImmutable();
        try{
            Element y = pairing.getZr().newRandomElement().getImmutable();
            S2 = g.powZn(y).getImmutable();
            byte[] Hbytes = getHbytes(m,B);
            Element hash = PairingUtils.MapByteArrayToGroup(pairing,Hbytes,PairingUtils.PairingGroupType.G2).getImmutable();
            S1 = hash.powZn(y).getImmutable();
            for(int i=0;i<attributes.length;i++){
                S1 = S1.mul(Dx.get(B[i]).powZn(lagrangePolynomial.calCoef(pairing,attributes,attributes[i]))).getImmutable();
            }
        }catch (Exception e){
            System.out.println("error:"+e.getMessage());
            return new SignParameter(null,null);
        }
        return new SignParameter(S1,S2);
    }

    public boolean Verify(Element m,String[] B,SignParameter sign){
        int len = B.length;
        int[] attributes = new int[len];
        for(int i=0;i<len;i++){
            attributes[i] = Integer.parseInt(B[i]);
        }

        Element L = pairing.pairing(g,sign.S1);

        byte[] Hbytes = getHbytes(m,B);
        Element hash = PairingUtils.MapByteArrayToGroup(pairing,Hbytes,PairingUtils.PairingGroupType.G2).getImmutable();
        Element R = pairing.pairing(g0,h2).mul(pairing.pairing(sign.S2,hash)).getImmutable();
        Element A = pairing.getG1().newOneElement().getImmutable();
        for(String att : B){
            int x = Integer.valueOf(att);
            A = A.mul(Zx.get(att).powZn(lagrangePolynomial.calCoef(pairing,attributes,x))).getImmutable();
        }
        R = R.mul(pairing.pairing(A,h1)).getImmutable();
        if(L.equals(R)){
            return true;
        }
        return false;
    }
}
