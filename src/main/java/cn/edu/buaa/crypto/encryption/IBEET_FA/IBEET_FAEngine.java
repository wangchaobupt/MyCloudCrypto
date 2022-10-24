package cn.edu.buaa.crypto.encryption.IBEET_FA;

import cn.edu.buaa.crypto.encryption.GT.ELGamal;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.omg.Messaging.SYNC_WITH_TRANSPORT;

import java.util.Arrays;

public class IBEET_FAEngine {
    private static IBEET_FAEngine engine;
    private Pairing pairing;
    private Element g;
    private Element Y1,Y2;

    public static IBEET_FAEngine getInstance(){
        if(engine == null){
            engine = new IBEET_FAEngine();
        }
        return engine;
    }
    public Pairing getPairing() {return this.pairing;}

    public void Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.g = this.pairing.getG1().newRandomElement().getImmutable();
    }

    public MasterSecretKey KeyGen(){
        Element s1 = pairing.getZr().newRandomElement().getImmutable();
        Element s2 = pairing.getZr().newRandomElement().getImmutable();
        this.Y1 = this.g.powZn(s1);
        this.Y2 = this.g.powZn(s2);
        return new MasterSecretKey(s1,s2);
    }

    public DecryptionKey Extract(String ID,MasterSecretKey msk){
        Element dk1 = PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1).powZn(msk.getS1()).getImmutable();
        Element dk2 = PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1).powZn(msk.getS2()).getImmutable();
        return new DecryptionKey(dk1,dk2);
    }

    public byte[] getH2(Element e,Element c1,Element c2,Element c4){
        byte[] ebytes = e.toBytes();
        byte[] c1bytes = c1.toBytes();
        byte[] c2bytes = c2.toBytes();
        byte[] c4bytes = c4.toBytes();
        byte[] res = new byte[ebytes.length+c1bytes.length+c2bytes.length+c4bytes.length];
        System.arraycopy(ebytes,0,res,0,ebytes.length);
        System.arraycopy(c1bytes,0,res,ebytes.length,c1bytes.length);
        System.arraycopy(c2bytes,0,res,ebytes.length+c1bytes.length,c2bytes.length);
        System.arraycopy(c4bytes,0,res,ebytes.length+c1bytes.length+c2bytes.length,c4bytes.length);
        return res;
    }

    public byte[] getH3(Element e,Element c1,Element c2,byte[] c3,Element c4){
        byte[] ebytes = e.toBytes();
        byte[] c1bytes = c1.toBytes();
        byte[] c2bytes = c2.toBytes();
        byte[] c4bytes = c4.toBytes();
        byte[] res = new byte[ebytes.length+c1bytes.length+c2bytes.length+c3.length+c4bytes.length];
        System.arraycopy(ebytes,0,res,0,ebytes.length);
        System.arraycopy(c1bytes,0,res,ebytes.length,c1bytes.length);
        System.arraycopy(c2bytes,0,res,ebytes.length+c1bytes.length,c2bytes.length);
        System.arraycopy(c3,0,res,ebytes.length+c1bytes.length+c2bytes.length,c3.length);
        System.arraycopy(c4bytes,0,res,ebytes.length+c1bytes.length+c2bytes.length+c3.length,c4bytes.length);
        return res;
    }

    public CipherText Encrypt(Element message,String ID){
        Element r1 = pairing.getZr().newRandomElement().getImmutable();
        Element r2 = pairing.getZr().newRandomElement().getImmutable();
        Element r3 = pairing.getZr().newRandomElement().getImmutable();

        Element c1 = this.g.powZn(r1).getImmutable();
        Element c2 = this.g.powZn(r2).getImmutable();
        Element c4 = this.g.powZn(r3).getImmutable();

        byte[] mrbytes = message.powZn(r1).getImmutable().toBytes();
        byte[] h1bytes = PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1)
                .powZn(r1).powZn(r2).getImmutable().toBytes();
        byte[] mh = new byte[mrbytes.length + h1bytes.length];
        System.arraycopy(mrbytes,0,mh,0,mrbytes.length);
        System.arraycopy(h1bytes,0,mh,mrbytes.length,h1bytes.length);
        Element e2 = this.pairing.pairing(
                PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1),this.Y1
        ).powZn(r3).getImmutable();
        byte[] c3 = PairingUtils.Xor(mh,getH2(e2,c1,c2,c4));


        byte[] mbytes = message.toBytes();
        byte[] rbytes = r1.toBytes();
        byte[] mr = new byte[mbytes.length + rbytes.length];
        System.arraycopy(mbytes,0,mr,0,mbytes.length);
        System.arraycopy(rbytes,0,mr,mbytes.length,rbytes.length);
        Element e3 = this.pairing.pairing(
                PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1),this.Y2
        ).powZn(r3).getImmutable();
        byte[] c5 = PairingUtils.Xor(mr,getH3(e3,c1,c2,c3,c4));

        return new CipherText(c1,c2,c4,c3,c5);
    }

    public PlainText Decrypt(CipherText ct,String ID,DecryptionKey dk){
        Element e3 = this.pairing.pairing(dk.getDk2(),ct.C4).getImmutable();
        byte[] Mr = PairingUtils.Xor(ct.C5,getH3(e3,ct.C1,ct.C2,ct.C3,ct.C4));
        Element e2 = this.pairing.pairing(dk.getDk1(),ct.C4).getImmutable();
        byte[] AB = PairingUtils.Xor(ct.C3,getH2(e2,ct.C1,ct.C2,ct.C4));


        byte[] mbytes = Arrays.copyOfRange(Mr, 0, 64);
        byte[] rbytes = Arrays.copyOfRange(Mr,64,Mr.length);
        byte[] Abytes = Arrays.copyOfRange(AB, 0, 64);
        byte[] Bbytes = Arrays.copyOfRange(AB,64,Mr.length);
        Element m = this.pairing.getG1().newElementFromBytes(mbytes).getImmutable();
        Element r = this.pairing.getZr().newElementFromBytes(rbytes).getImmutable();
        Element A = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();
        Element B = this.pairing.getG1().newElementFromBytes(Bbytes).getImmutable();

        if(ct.C1.isEqual(this.g.powZn(r).getImmutable())){
            if(A.isEqual(m.powZn(r).getImmutable())){
                if(this.pairing.pairing(B,this.g).isEqual(
                        this.pairing.pairing(PairingUtils.MapStringToGroup(this.pairing,ID,PairingUtils.PairingGroupType.G1).powZn(r),ct.C2)
                )){
                    return new PlainText(true,m);
                }
            }
        }
        return new PlainText(false,this.pairing.getG1().newZeroElement().getImmutable());
    }

    public Auth1Parameter Aut1(DecryptionKey dk){
        return new Auth1Parameter(dk.getDk1());
    }

    public int Test1(CipherText CT1,Auth1Parameter td1,CipherText CT2,Auth1Parameter td2){
        Element e2 = this.pairing.pairing(td1.getTd(),CT1.C4).getImmutable();
        byte[] AB = PairingUtils.Xor(CT1.C3,getH2(e2,CT1.C1,CT1.C2,CT1.C4));
        byte[] Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr1 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        e2 = this.pairing.pairing(td2.getTd(),CT2.C4).getImmutable();
        AB = PairingUtils.Xor(CT2.C3,getH2(e2,CT2.C1,CT2.C2,CT2.C4));
        Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr2 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        if(this.pairing.pairing(Mr1,CT2.C1).isEqual(
                this.pairing.pairing(Mr2,CT1.C1)
        )){
            return 1;
        }
        return 0;
    }

    public Auth2Parameter Aut2(DecryptionKey dk,CipherText ct){
        Element e2 = this.pairing.pairing(dk.getDk1(),ct.C4).getImmutable();
        return new Auth2Parameter(getH2(e2,ct.C1,ct.C2,ct.C4));
    }

    public int Test2(CipherText CT1,Auth2Parameter td1,CipherText CT2,Auth2Parameter td2){
        byte[] AB = PairingUtils.Xor(CT1.C3,td1.getTd());
        byte[] Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr1 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        AB = PairingUtils.Xor(CT2.C3,td2.getTd());
        Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr2 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        if(this.pairing.pairing(Mr1,CT2.C1).isEqual(
                this.pairing.pairing(Mr2,CT1.C1)
        )){
            return 1;
        }
        return 0;
    }

    public Auth4Parameter Aut4(DecryptionKey dk,CipherText ct){
        Element e2 = this.pairing.pairing(dk.getDk1(),ct.C4).getImmutable();
        return new Auth4Parameter(getH2(e2,ct.C1,ct.C2,ct.C4),dk.getDk1());
    }

    public int Test4(CipherText CT1,Auth4Parameter td1,CipherText CT2,Auth4Parameter td2){
        byte[] AB = PairingUtils.Xor(CT1.C3,td1.getTd2());
        byte[] Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr1 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        Element e2 = this.pairing.pairing(td2.getTd1(),CT2.C4).getImmutable();
        AB = PairingUtils.Xor(CT2.C3,getH2(e2,CT2.C1,CT2.C2,CT2.C4));
        Abytes = Arrays.copyOfRange(AB, 0, 64);
        Element Mr2 = this.pairing.getG1().newElementFromBytes(Abytes).getImmutable();

        if(this.pairing.pairing(Mr1,CT2.C1).isEqual(
                this.pairing.pairing(Mr2,CT1.C1)
        )){
            return 1;
        }
        return 0;
    }
}
