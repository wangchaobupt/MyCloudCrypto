package cn.edu.buaa.crypto.encryption.AOACE;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

public class OACEEngine {
    private static OACEEngine engine;
    private LSSSLW10Engine accessControlEngine;
    private Element g,h,u,v,w,egg_alpha;
    private Pairing pairing;

    public static OACEEngine getInstance(){
        if(engine == null){
            engine = new OACEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public static boolean intersection(String[] S,String[] R){
        HashSet<String> set1 = new HashSet<String>();
        for(String i:S){
            set1.add(i);
        }
        HashSet<String> set2 = new HashSet<String>();
        for(String i:R){
            if(set1.contains(i))
                set2.add(i);
        }
        if(set2.size() == R.length) return true;
        else return false;
    }

    public Element[] addList(Element[] a,Element[] b){
        int size = b.length;
        Element[] res = new Element[size];
        for(int i=0;i<size;i++){
            res[i] = a[i].add(b[i]).getImmutable();
        }
        return res;
    }

    public Element[] mulList(Element[] a,Element[] b){
        int size = b.length;
        Element[] res = new Element[size];
        for(int i=0;i<size;i++){
            res[i] = a[i].mul(b[i]).getImmutable();
        }
        return res;
    }

    public byte[] getCCbytes(Ciphertext c,AuthenticationCiphertext c1){
        Map<String, Element> Cs1 = c.Cs1;
        Map<String, Element> Cs2 = c.Cs2;
        Map<String, Element> Cs3 = c.Cs3;
        Map<String, Element> Cs4 = c.Cs4;
        Map<String, Element> Cs5 = c.Cs5;
        Map<String, Element> Es2 = c1.Es2;
        Map<String, Element> Es3 = c1.Es3;
        int size = 4 + Cs1.size()*5 + Es2.size()*2;
        byte[][] CCbytes = new byte[size][];
        CCbytes[0] = c.C.toBytes();
        CCbytes[1] = c.C0.toBytes();
        CCbytes[2] = c1.E0.toBytes();
        CCbytes[3] = c1.E1.toBytes();
        int i = 4;
        for(String att : Cs1.keySet()){
            CCbytes[i++] = Cs1.get(att).toBytes();
            CCbytes[i++] = Cs2.get(att).toBytes();
            CCbytes[i++] = Cs3.get(att).toBytes();
            CCbytes[i++] = Cs4.get(att).toBytes();
            CCbytes[i++] = Cs5.get(att).toBytes();
        }
        for(String att : Es2.keySet()){
            CCbytes[i++] = Es2.get(att).toBytes();
            CCbytes[i++] = Es3.get(att).toBytes();
        }
        int len = 0;
        for(i=0;i<size;i++){
            len += CCbytes[i].length;
        }
        byte[] res = new byte[len];
        int start = 0;
        for(i=0;i<size;i++){
            System.arraycopy(CCbytes[i],0,res,start,CCbytes[i].length);
            start+=CCbytes[i].length;
        }
        return res;
    }

    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        this.accessControlEngine = LSSSLW10Engine.getInstance();
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG1().newRandomElement().getImmutable();
        u = pairing.getG1().newRandomElement().getImmutable();
        v = pairing.getG1().newRandomElement().getImmutable();
        w = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        egg_alpha = pairing.pairing(g,g).powZn(alpha).getImmutable();
        return new MasterSecretKey(alpha);
    }

    public UserKey Keygen(MasterSecretKey msk, String[] A){
        Element sigma = pairing.getZr().newRandomElement().getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();
        RetrieveKey rk = new RetrieveKey(sigma);
        Element K0 = g.powZn(msk.alpha.div(sigma)).mul(w.powZn(r.div(sigma))).getImmutable();
        Element K1 = g.powZn(r).getImmutable();
        Map<String, Element> Ks2 = new HashMap<String, Element>();
        Map<String, Element> Ks3 = new HashMap<String, Element>();

        for (String att : A){
            Element elementatt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Ks2.put(att,g.powZn(ri).getImmutable());
            Ks3.put(att,(u.powZn(elementatt).mul(h)).powZn(ri).mul(v.powZn(r.negate())).getImmutable());
        }
        TransformKey tk = new TransformKey(K0,K1,Ks2,Ks3,A);
        return new UserKey(rk,tk);
    }

    public IntermediateCiphertext Encrypt_off(int N){
        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element key = egg_alpha.powZn(s).getImmutable();
        Element C0 = g.powZn(s).getImmutable();
        Element[] delta = new Element[N];
        Element[] x = new Element[N];
        Element[] xi = new Element[N];
        Element[] Cs1 = new Element[N];
        Element[] Cs2 = new Element[N];
        Element[] Cs3 = new Element[N];
        for(int i=0;i<N;i++){
            delta[i] = pairing.getZr().newRandomElement().getImmutable();
            x[i] = pairing.getZr().newRandomElement().getImmutable();
            xi[i] = pairing.getZr().newRandomElement().getImmutable();
            Cs1[i] = w.powZn(delta[i]).mul(v.powZn(xi[i])).getImmutable();
            Cs2[i] = (u.powZn(x[i]).mul(h)).powZn(xi[i].negate()).getImmutable();
            Cs3[i] = g.powZn(xi[i]).getImmutable();
        }
        return new IntermediateCiphertext(s,key,C0,delta,xi,x,Cs1,Cs2,Cs3);
    }

    public Ulist getHalfU(BasicList basicList) throws IOException, ClassNotFoundException {
        Socket socketConnection = new Socket("127.0.0.1", 8888);
        ObjectOutputStream out = new ObjectOutputStream(socketConnection.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socketConnection.getInputStream());
        out.write(2);
        out.writeObject(basicList);
        out.flush();
        Ulist ulist = (Ulist) in.readObject();
        socketConnection.close();
        return ulist;
    }

    public PartialCiphertext Encrypt_out(int l,TransformKey tk){
        IntermediateCiphertext it = Encrypt_off(l);
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element L0 = w.powZn(r).getImmutable();
        Element L1 = tk.K1.mul(g.powZn(r)).getImmutable();
        Map<String, Element> Ls2 = new HashMap<String, Element>();
        Map<String, Element> Ls3 = new HashMap<String, Element>();
        String[] As = tk.A;
        Map<String, Element> Ks2 = tk.Ks2;
        Map<String, Element> Ks3 = tk.Ks3;

        for (String att : As){
            Element elementatt = PairingUtils.MapStringToGroup(pairing, att, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Ls2.put(att,Ks2.get(att).mul(g.powZn(ri)).getImmutable());
            Ls3.put(att,Ks3.get(att).mul((u.powZn(elementatt).mul(h)).powZn(ri).mul(v.powZn(r.negate()))).getImmutable());
        }
        return new PartialCiphertext(it,tk.K0,L0,L1,Ls2,Ls3);
    }

    public CiphertextParameter Encrypt_on(IntermediateCiphertext it,PartialCiphertext at,Element m,String accessPolicy,RetrieveKey rk,String[] Ac) throws PolicySyntaxException {
        IntermediateCiphertext it1 = at.it;
        Element s = it.s.add(it1.s).getImmutable();
        Element key = it.key.mul(it1.key).getImmutable();
        Element C0 = it.C0.mul(it1.C0).getImmutable();
        Element[] delta = addList(it.delta,it1.delta);
        Element[] xi = addList(it.xi,it1.xi);
        int size = xi.length;
        Element[] x = new Element[size];
        for(int i=0;i<size;i++){
            x[i] = it.x[i].mul(it.xi[i]).add(it1.x[i].mul(it1.xi[i])).div(xi[i]);
        }
        Element[] Ci1 = mulList(it.Cs1,it1.Cs1);
        Element[] Ci2 = mulList(it.Cs2,it1.Cs2);
        Element[] Ci3 = mulList(it.Cs3,it1.Cs3);
        Element C = m.mul(key).getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();
        Map<String, Element> Cs4 = new HashMap<String, Element>();
        Map<String, Element> Cs5 = new HashMap<String, Element>();

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        int index = 0;
        String[] Am = new String[lambdas.size()];
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Cs1.put(rho,Ci1[index]);
            Cs2.put(rho,Ci2[index]);
            Cs3.put(rho,Ci3[index]);
            Cs4.put(rho,lambdas.get(rho).sub(delta[index]).getImmutable());
            Cs5.put(rho,xi[index].mul(x[index].sub(elementRho)).getImmutable());
            Am[index] = rho;
            index++;
        }
        Ciphertext c = new Ciphertext(C,C0,Cs1,Cs2,Cs3,Cs4,Cs5,accessPolicy,Am);

        Element phi = pairing.getZr().newRandomElement().getImmutable();
        Element E0 = g.powZn(phi).getImmutable();
        Map<String, Element> Es2 = new HashMap<String, Element>();
        Map<String, Element> Es3 = new HashMap<String, Element>();
        Map<String, Element> Ls2 = at.Ls2;
        Map<String, Element> Ls3 = at.Ls3;
        for(String att : Ac){
            Es2.put(att,Ls2.get(att));
            Es3.put(att,Ls3.get(att));
        }
        AuthenticationCiphertext c1 = new AuthenticationCiphertext(E0,at.L1,Es2,Es3,Ac);

        Element Hash_CC = PairingUtils.MapByteArrayToGroup(this.pairing,getCCbytes(c,c1),PairingUtils.PairingGroupType.G1);
        Element c2 = at.K0.powZn(rk.sigma).mul(at.L0).mul(Hash_CC.powZn(phi)).getImmutable();
        AuthenticationTag pai = new AuthenticationTag(c1,c2);
        return new CiphertextParameter(c,pai);
    }
/*
    public Ciphertext Sanitize(CiphertextParameter ct) throws Exception {
        Ciphertext c = ct.c;
        AuthenticationCiphertext c1 = ct.pai.c1;
        Element c2 = ct.pai.c2;
        String[] Ac = c1.Ac;
        String[] Am = c.attributes;
        String accessPolicy = "";
        for(String att : Ac){
            if(att.equals(Ac[Ac.length-1]))
                accessPolicy += att;
            else
                accessPolicy += att + " and ";
        }

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> mus = accessControlEngine.secretSharing(pairing, pairing.getZr().newOneElement(), accessControlParameter);

        Map<String, Element> Ts1 = new HashMap<String, Element>();
        Map<String, Element> Ts2 = new HashMap<String, Element>();
        Map<String, Element> Ts3 = new HashMap<String, Element>();

        //System.out.println("rho:");
        for (String rho : mus.keySet()) {
            //System.out.println(rho);
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ki = pairing.getZr().newRandomElement().getImmutable();
            Ts1.put(rho, w.powZn(mus.get(rho)).mul(v.powZn(ki)).getImmutable());
            Ts2.put(rho, (u.powZn(elementRho).mul(h)).powZn(ki.negate()).getImmutable());
            Ts3.put(rho, g.powZn(ki).getImmutable());
        }

        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, Ac, accessControlParameter);
        Element sumF = pairing.getGT().newOneElement().getImmutable();
        System.out.println("omega:");
        for (String att : omegaElementsMap.keySet()) {

            Element w_i = omegaElementsMap.get(att);
            System.out.println(att + " : " + w_i);
            sumF = sumF.mul(pairing.pairing(Ts1.get(att),c1.E1).mul(pairing.pairing(Ts2.get(att),c1.Es2.get(att)))
                    .mul(pairing.pairing(Ts3.get(att),c1.Es3.get(att))).powZn(w_i)).getImmutable();
        }
        Element Hash_CC = PairingUtils.MapByteArrayToGroup(this.pairing,getCCbytes(c,c1),PairingUtils.PairingGroupType.G1);
        Element Y0 = pairing.pairing(g,c2).div(
                pairing.pairing(Hash_CC,c1.E0).mul(sumF)
        ).getImmutable();
        if(!Y0.equals(egg_alpha)){
            throw new Exception("Y0 not satisfied");
        }

        if(!intersection(Ac,Am)){
            throw new Exception("Ac not satisfied Am");
        }

        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element C = c.C.mul(egg_alpha.powZn(t)).getImmutable();
        Element C0 = c.C0.mul(g.powZn(t)).getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();
        Map<String, Element> cs1 = c.Cs1;
        Map<String, Element> cs2 = c.Cs2;
        Map<String, Element> cs3 = c.Cs3;


        accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(c.accessPolicy);
        stringRhos = ParserUtils.GenerateRhos(c.accessPolicy);
        accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, t, accessControlParameter);
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element di = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho, cs1.get(rho).mul(w.powZn(lambdas.get(rho))).mul(v.powZn(di)).getImmutable());
            Cs2.put(rho, cs2.get(rho).mul((u.powZn(elementRho).mul(h)).powZn(di.negate())).getImmutable());
            Cs3.put(rho, cs3.get(rho).mul(g.powZn(di)).getImmutable());
        }
        //return new SanitizedCiphertext(C,C0,Cs1,Cs2,Cs3,c.Cs4,c.Cs5,c.accessPolicy);
        return new Ciphertext(C,C0,Cs1,Cs2,Cs3,c.Cs4,c.Cs5,c.accessPolicy,c.attributes);
    }

 */
    public Element getHalfF(Flist flist) throws IOException {
        Socket socketConnection = new Socket("127.0.0.1", 8888);
        ObjectOutputStream out = new ObjectOutputStream(socketConnection.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socketConnection.getInputStream());
        out.write(1);
        out.writeObject(flist);
        out.flush();
        byte[] data = new byte[10240];
        in.read(data);
        socketConnection.close();
        return pairing.getGT().newElementFromBytes(data);
    }

    public Clist getHalfB(Blist blist) throws IOException, ClassNotFoundException {
        Socket socketConnection = new Socket("127.0.0.1", 8888);
        ObjectOutputStream out = new ObjectOutputStream(socketConnection.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socketConnection.getInputStream());
        out.write(2);
        out.writeObject(blist);
        out.flush();
        Clist clist = (Clist) in.readObject();
        socketConnection.close();
        return clist;
    }

    public Ciphertext Sanitize(CiphertextParameter ct) throws Exception {
        Ciphertext c = ct.c;
        AuthenticationCiphertext c1 = ct.pai.c1;
        Element c2 = ct.pai.c2;
        String[] Ac = c1.Ac;
        String[] Am = c.attributes;
        String accessPolicy = "";
        for(String att : Ac){
            if(att.equals(Ac[Ac.length-1]))
                accessPolicy += att;
            else
                accessPolicy += att + " and ";
        }

        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> mus = accessControlEngine.secretSharing(pairing, pairing.getZr().newOneElement(), accessControlParameter);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, Ac, accessControlParameter);

        Map<String, Element> Es2_1 = new HashMap<String, Element>();
        Map<String, Element> Es2_2 = new HashMap<String, Element>();
        Map<String, Element> Es3_1 = new HashMap<String, Element>();
        Map<String, Element> Es3_2 = new HashMap<String, Element>();
        Map<String, Element> mus_1 = new HashMap<String, Element>();
        Map<String, Element> mus_2 = new HashMap<String, Element>();
        Map<String, Element> w_i1 = new HashMap<String, Element>();
        Map<String, Element> w_i2 = new HashMap<String, Element>();

        for(int i=0;i<Ac.length/2;i++){
            String att = Ac[i];
            Es2_1.put(att,c1.Es2.get(att));
            Es3_1.put(att,c1.Es3.get(att));
            mus_1.put(att,mus.get(att));
            w_i1.put(att,omegaElementsMap.get(att));
        }

        for(int i=Ac.length/2;i<Ac.length;i++){
            String att = Ac[i];
            Es2_2.put(att,c1.Es2.get(att));
            Es3_2.put(att,c1.Es3.get(att));
            mus_2.put(att,mus.get(att));
            w_i2.put(att,omegaElementsMap.get(att));
        }

        Flist flist = new Flist(c1.E1, Es2_2, Es3_2, mus_2, w_i2, w, v, u, h, g);
        Element sumF_2 = getHalfF(flist);

        Map<String, Element> Ts1 = new HashMap<String, Element>();
        Map<String, Element> Ts2 = new HashMap<String, Element>();
        Map<String, Element> Ts3 = new HashMap<String, Element>();

        for (String rho : mus_1.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ki = pairing.getZr().newRandomElement().getImmutable();
            Ts1.put(rho, w.powZn(mus_1.get(rho)).mul(v.powZn(ki)).getImmutable());
            Ts2.put(rho, (u.powZn(elementRho).mul(h)).powZn(ki.negate()).getImmutable());
            Ts3.put(rho, g.powZn(ki).getImmutable());
        }

        Element sumF = pairing.getGT().newOneElement().getImmutable();
        for (String att : w_i1.keySet()) {
            Element w_i = w_i1.get(att);
            Element tmp = pairing.pairing(Ts1.get(att),c1.E1).mul(pairing.pairing(Ts2.get(att),c1.Es2.get(att)))
                    .mul(pairing.pairing(Ts3.get(att),c1.Es3.get(att))).powZn(w_i).getImmutable();
            sumF = sumF.mul(tmp).getImmutable();
        }
        sumF = sumF.mul(sumF_2);

        Element Hash_CC = PairingUtils.MapByteArrayToGroup(this.pairing,getCCbytes(c,c1),PairingUtils.PairingGroupType.G1);
        Element Y0 = pairing.pairing(g,c2).div(
                pairing.pairing(Hash_CC,c1.E0).mul(sumF)
        ).getImmutable();
        if(!Y0.equals(egg_alpha)){
            throw new Exception("Y0 not satisfied");
        }

        if(!intersection(Ac,Am)){
            throw new Exception("Ac not satisfied Am");
        }

        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element C = c.C.mul(egg_alpha.powZn(t)).getImmutable();
        Element C0 = c.C0.mul(g.powZn(t)).getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Map<String, Element> Cs2 = new HashMap<String, Element>();
        Map<String, Element> Cs3 = new HashMap<String, Element>();
        Map<String, Element> cs1 = c.Cs1;
        Map<String, Element> cs2 = c.Cs2;
        Map<String, Element> cs3 = c.Cs3;

        accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(c.accessPolicy);
        stringRhos = ParserUtils.GenerateRhos(c.accessPolicy);
        accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, t, accessControlParameter);

        Map<String, Element> cs1_1 = new HashMap<String, Element>();
        Map<String, Element> cs1_2 = new HashMap<String, Element>();
        Map<String, Element> cs2_1 = new HashMap<String, Element>();
        Map<String, Element> cs2_2 = new HashMap<String, Element>();
        Map<String, Element> cs3_1 = new HashMap<String, Element>();
        Map<String, Element> cs3_2 = new HashMap<String, Element>();
        Map<String, Element> lambdas1 = new HashMap<String, Element>();
        Map<String, Element> lambdas2 = new HashMap<String, Element>();
        int index = 0;
        int size = lambdas.size();
        for(String rho : lambdas.keySet()){
            if(index < size / 2){
                lambdas1.put(rho, lambdas.get(rho));
                cs1_1.put(rho, cs1.get(rho));
                cs2_1.put(rho, cs2.get(rho));
                cs3_1.put(rho, cs3.get(rho));
            }else {
                lambdas2.put(rho, lambdas.get(rho));
                cs1_2.put(rho, cs1.get(rho));
                cs2_2.put(rho, cs2.get(rho));
                cs3_2.put(rho, cs3.get(rho));
            }
            index++;
        }
        Blist blist = new Blist(cs1_2,cs2_2,cs3_2,lambdas2,w,v,u,h,g);
        Clist clist = getHalfB(blist);
        Map<String, Element> Cs1_2 = clist.getMap(clist.bCs1,pairing);
        Map<String, Element> Cs2_2 = clist.getMap(clist.bCs2,pairing);
        Map<String, Element> Cs3_2 = clist.getMap(clist.bCs3,pairing);

        for (String rho : lambdas1.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element di = pairing.getZr().newRandomElement().getImmutable();
            Cs1.put(rho, cs1_1.get(rho).mul(w.powZn(lambdas1.get(rho))).mul(v.powZn(di)).getImmutable());
            Cs2.put(rho, cs2_1.get(rho).mul((u.powZn(elementRho).mul(h)).powZn(di.negate())).getImmutable());
            Cs3.put(rho, cs3_1.get(rho).mul(g.powZn(di)).getImmutable());
        }

        for(String rho : Cs1_2.keySet()){
            Cs1.put(rho, Cs1_2.get(rho));
            Cs2.put(rho, Cs2_2.get(rho));
            Cs3.put(rho, Cs3_2.get(rho));
        }

        return new Ciphertext(C,C0,Cs1,Cs2,Cs3,c.Cs4,c.Cs5,c.accessPolicy,c.attributes);
    }

    public TransformedCiphertext Decrypt_out(Ciphertext st, TransformKey tk) throws PolicySyntaxException, UnsatisfiedAccessControlException {
        Map<String, Element> Cs1 = st.Cs1;
        Map<String, Element> Cs2 = st.Cs2;
        Map<String, Element> Cs3 = st.Cs3;
        Map<String, Element> Cs4 = st.Cs4;
        Map<String, Element> Cs5 = st.Cs5;
        Map<String, Element> Ks2 = tk.Ks2;
        Map<String, Element> Ks3 = tk.Ks3;
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(st.accessPolicy);
        String[] stringRhos = ParserUtils.GenerateRhos(st.accessPolicy);
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicyIntArrays, stringRhos);
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, tk.A, accessControlParameter);
        Element sumZ = pairing.getGT().newOneElement().getImmutable();
        for (String att : omegaElementsMap.keySet()) {
            Element w_i = omegaElementsMap.get(att);
            Element C1 = Cs1.get(att).mul(w.powZn(Cs4.get(att))).getImmutable();
            Element C2 = Cs2.get(att).mul(u.powZn(Cs5.get(att))).getImmutable();
            Element C3 = Cs3.get(att).getImmutable();
            sumZ = sumZ.mul((pairing.pairing(C1,tk.K1).mul(pairing.pairing(C2,Ks2.get(att))).mul(pairing.pairing(C3,Ks3.get(att)))).powZn(w_i)).getImmutable();
        }
        Element Y2 = pairing.pairing(st.C0,tk.K0);
        return new TransformedCiphertext(st.C,sumZ,Y2);
    }

    public Element Decrypt_on(TransformedCiphertext rt, RetrieveKey rk){
        Element key = rt.Y2.powZn(rk.sigma).div(rt.Y1).getImmutable();
        Element m = rt.C.div(key);
        return m;
    }
}
