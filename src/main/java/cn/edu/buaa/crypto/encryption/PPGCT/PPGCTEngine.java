package cn.edu.buaa.crypto.encryption.PPGCT;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PPGCTEngine {
    private static PPGCTEngine engine;
    private Pairing pairing;
    private Element g;

    public static PPGCTEngine getInstance() {
        if (engine == null) {
            engine = new PPGCTEngine();
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
        List<Element> ts = new ArrayList<Element>();
        for(int i=0;i<s.size();i++){
            ts.add(PairingUtils.MapByteArrayToGroup(this.pairing,
                    PairingUtils.MapByteArrayToGroup(this.pairing,s.get(i).toBytes(),PairingUtils.PairingGroupType.G1).powZn(rs).getImmutable().toBytes(),
                    PairingUtils.PairingGroupType.G1).getImmutable());
        }
        return new OfflineParameter(rs,ts);
    }

    public C_OnlineParameter C_online(List<Element> c){
        Element[] rc = new Element[c.size()];
        List<Element> a = new ArrayList<Element>();
        for(int i=0;i<c.size();i++){
            rc[i] = this.pairing.getZr().newRandomElement().getImmutable();
            a.add(PairingUtils.MapByteArrayToGroup(this.pairing,c.get(i).toBytes(),PairingUtils.PairingGroupType.G1).powZn(rc[i]).getImmutable());
        }
        return new C_OnlineParameter(rc,a);
    }

    public List<Element> S_online(List<Element> a,OfflineParameter S){
        List<Element> a1 = new ArrayList<Element>();
        for (int i=0;i<a.size();i++){
            a1.add(a.get(i).powZn(S.getRs()).getImmutable());
        }
        return a1;
    }
/*
    public List<Element> Test(List<Element> c,List<Element> a1,List<Element> ts,Element[] Rc){
        Element tc;
        List<Element> res = new ArrayList<Element>();
        for(int i=0;i<a1.size();i++){
            tc = PairingUtils.MapByteArrayToGroup(this.pairing,a1.get(i).powZn(Rc[i].invert()).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable();
            for(int j=0;j<ts.size();j++){
                if(tc.equals(ts.get(j))){
                    res.add(c.get(i));
                    ts.remove(j);
                    break;
                }
            }
        }
        return res;
    }

 */
    public List<Element> Test(List<Element> c,List<Element> a1,Element[] Rc){
        List<Element> tc = new ArrayList<Element>();

        for(int i=0;i<a1.size();i++){
            tc.add(PairingUtils.MapByteArrayToGroup(this.pairing,a1.get(i).powZn(Rc[i].invert()).toBytes(),PairingUtils.PairingGroupType.G1).getImmutable());
        }
        return tc;
    }
}
