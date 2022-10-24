package cn.edu.buaa.crypto.encryption.PPGPT_new;

import cn.edu.buaa.crypto.encryption.GT.ELGamal;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PPGPTEngine {
    private static PPGPTEngine engine;
    private Pairing pairing;
    private Element g;


    public static PPGPTEngine getInstance() {
        if (engine == null) {
            engine = new PPGPTEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}
    public void Init(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
    }

    public OfflineParameter S_offline(List<Element> s){
        Collections.shuffle(s);
        Element rs = this.pairing.getZr().newRandomElement().getImmutable();
        Element rs1 = this.pairing.getZr().newRandomElement().getImmutable();
        Element Y = this.g.powZn(rs).getImmutable();
        List<Element> ks = new ArrayList<Element>();

        for(int i=0;i<s.size();i++){
            ks.add(PairingUtils.MapByteArrayToGroup(this.pairing,s.get(i).toBytes(),PairingUtils.PairingGroupType.G1).powZn(rs1).getImmutable());
        }
        return new OfflineParameter(rs,rs1,Y,ks);
    }

    public OfflineParameter C_offline(List<Element> c){
        Element rc = this.pairing.getZr().newRandomElement().getImmutable();
        Element rc1 = this.pairing.getZr().newRandomElement().getImmutable();
        Element X = this.g.powZn(rc).getImmutable();
        List<Element> kc = new ArrayList<Element>();

        for(int i=0;i<c.size();i++){
            kc.add(PairingUtils.MapByteArrayToGroup(this.pairing,c.get(i).toBytes(),PairingUtils.PairingGroupType.G1).powZn(rc1).getImmutable());
        }
        return new OfflineParameter(rc,rc1,X,kc);
    }

    public S_OnlineParameter S_online(Element X,List<Element> a,OfflineParameter S){
        List<Element> a1 = new ArrayList<Element>();
        for(int i=0;i<a.size();i++){
            a1.add(a.get(i).powZn(S.getR1()).getImmutable());
        }
        Collections.shuffle(a1);

        List<Element> ts = new ArrayList<Element>();
        List<Element> ks = S.getK();
        for(int i=0;i<ks.size();i++){
            ts.add(PairingUtils.MapByteArrayToGroup(this.pairing,ks.get(i).mul(X.powZn(S.getR())).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }

        return new S_OnlineParameter(S.getY(),a1,ts);
    }

    /*
    public List<Element> C_online(S_OnlineParameter S, OfflineParameter C){
        List<Element> al = S.getAl();
        List<Element> ts = S.getTs();
        List<Element> res = new ArrayList<Element>();
        System.out.println("ts:");
        for(int i=0;i<ts.size();i++) System.out.println(ts.get(i));
        System.out.println("tc:");
        for(int i=0;i<al.size();i++){
            Element tmp = S.getY().powZn(C.getR()).mul(al.get(i).powZn(C.getR1().invert())).getImmutable();
            Element tc = PairingUtils.MapByteArrayToGroup(this.pairing,tmp.toBytes(),PairingUtils.PairingGroupType.G1).getImmutable();
            System.out.println(tc);
            for(int j=0;j<ts.size();j++){
                if(tc.equals(ts.get(j))){
                    res.add(tc);
                    ts.remove(j);
                    break;
                }
            }
            //tc.add(PairingUtils.MapByteArrayToGroup(this.pairing,tmp.toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }
        return res;
    }
     */
    public List<Element> C_online(S_OnlineParameter S, OfflineParameter C){
        List<Element> al = S.getAl();
        List<Element> ts = S.getTs();
        List<Element> tc = new ArrayList<Element>();
        for(int i=0;i<al.size();i++){
            Element tmp = S.getY().powZn(C.getR()).mul(al.get(i).powZn(C.getR1().invert())).getImmutable();
            tc.add(PairingUtils.MapByteArrayToGroup(this.pairing,tmp.toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }
        return tc;
    }
}
