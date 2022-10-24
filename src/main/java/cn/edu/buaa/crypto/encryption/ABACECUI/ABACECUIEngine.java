package cn.edu.buaa.crypto.encryption.ABACECUI;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class ABACECUIEngine {
    private static ABACECUIEngine engine;
    private Pairing pairing;
    private Element g1,g2,h1,h2,T1,T2;
    private int N = 4;

    public static ABACECUIEngine getInstance(){
        if(engine == null){
            engine = new ABACECUIEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public Element listPair(Element[] B,Element[] Bs){
        int size = B.length;
        Element res = pairing.getGT().newOneElement().getImmutable();
        for(int i=0;i<size;i++) {
            res = res.mul(pairing.pairing(B[i], Bs[i])).getImmutable();
        }
        return res;
    }

    public static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    public boolean intersection(String[] S,String[] R){
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

    public String getCTString(CipherText CT){
        String str = "";
        for(int i=0;i<3;i++){
            str += CT.ct0.get(i).toString();
        }
        Map<String, ArrayList<Element>> ct = CT.ct;
        for(String att:ct.keySet()){
            for(int l=0;l<3;l++){
                str += ct.get(att).get(l);
            }
        }
        return str;
    }
    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        g1 = pairing.getG1().newRandomElement().getImmutable();
        g2 = pairing.getG2().newRandomElement().getImmutable();
        ArrayList<Element> a = new ArrayList<Element>();
        ArrayList<Element> b = new ArrayList<Element>();
        ArrayList<Element> d = new ArrayList<Element>();
        ArrayList<Element> g_d = new ArrayList<Element>();
        for(int i=0;i<2;i++){
            a.add(pairing.getZr().newRandomElement().getImmutable());
            b.add(pairing.getZr().newRandomElement().getImmutable());
            d.add(pairing.getZr().newRandomElement().getImmutable());
            g_d.add(g1.powZn(d.get(i)).getImmutable());
        }
        d.add(pairing.getZr().newRandomElement().getImmutable());
        g_d.add(g1.powZn(d.get(2)).getImmutable());

        h1 = g2.powZn(a.get(0)).getImmutable();
        h2 = g2.powZn(a.get(1)).getImmutable();
        T1 = pairing.pairing(g1,g2).powZn(d.get(0).mul(a.get(0)).add(d.get(2))).getImmutable();
        T2 = pairing.pairing(g1,g2).powZn(d.get(1).mul(a.get(1)).add(d.get(2))).getImmutable();
        return new MasterSecretKey(a,b,g_d);
    }

    public UserKey KeyGen(MasterSecretKey msk, String id, String[] A) throws NoSuchAlgorithmException {
        ArrayList<Element> r = new ArrayList<Element>();
        for(int i=0;i<2;i++){
            r.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ArrayList<Element> br = new ArrayList<Element>();
        for(int i=0;i<2;i++){
            br.add(msk.b.get(i).mul(r.get(i)).getImmutable());
        }
        br.add(r.get(0).add(r.get(1)).getImmutable());

        ArrayList<Element> sk0 = new ArrayList<Element>();

        for(int i=0;i<3;i++){
            sk0.add(g2.powZn(br.get(i)).getImmutable());
        }

        Map<String, ArrayList<Element>> sk_y = new HashMap<String, ArrayList<Element>>();
        ArrayList<Element> a = msk.a;
        ElementPowPreProcessing ppp_g = g1.getElementPowPreProcessing();

        for (String attr: A) {
            ArrayList<Element> key = new ArrayList<Element>();
            Element sigma_attr = pairing.getZr().newRandomElement().getImmutable();
            for (int t=0; t<2; t++) {
                Element prod = pairing.getG1().newOneElement();
                Element a_t = a.get(t);
                for (int l=0; l<3; l++) {
                    String input_for_hash = attr + (l+1) + (t+1);
//                    Element hashed = PairingUtils.MapStringToGroup(pairing,input_for_hash,PairingUtils.PairingGroupType.G1);
                    Element hashed = pairing.getG1().newElement();
                    elementFromString(hashed, input_for_hash);  // H(y1t)
                    Element br_at = br.get(l).duplicate();      // b1*r1
                    br_at.div(a_t);                             // b1*r1/at
                    hashed.powZn(br_at);                        // H(y1t) ^ (b1*r1/at)
                    prod.mul(hashed);
                }
                Element sigma_attr_at = sigma_attr.duplicate();
                sigma_attr_at.div(a_t);                         // σ'/a_t
                Element g_sigma_attr_at = g1.duplicate();
                g_sigma_attr_at.powZn(sigma_attr_at);           // g ^ (σ'/a_t)
                prod.mul(g_sigma_attr_at);                      // prod *= (g ^ (σ'/a_t))
                key.add(prod);
            }
            Element minus_sigma_attr = sigma_attr.duplicate();
            minus_sigma_attr.mul(-1);                           // -σ
            key.add(g1.duplicate().powZn(minus_sigma_attr));     // g ^ (-σ)
            sk_y.put(attr, key);
        }

        ArrayList<Element> sk1 = new ArrayList<Element>();
        ArrayList<Element> g_d = msk.g_d;
        Element sigma = pairing.getZr().newRandomElement();
        for (int t=0; t<2; t++) {
            Element prod = g_d.get(t).duplicate();
            Element a_t = a.get(t);
            for (int l=0; l<3; l++) {
                String input_for_hash = "1" + (l+1) + (t+1);
//                Element hashed = PairingUtils.MapStringToGroup(pairing,input_for_hash,PairingUtils.PairingGroupType.G1);
                Element hashed = pairing.getG1().newElement();
                elementFromString(hashed, input_for_hash);
                Element br_at = br.get(l).duplicate();          // Br[l]
                br_at.div(a_t);                                 // Br[l] / a_t
                hashed.powZn(br_at);                            // H(01lt) ^ (Br[l] / a_t)
                prod.mul(hashed);                               // prod *= H(01lt) ^ (Br[l] / a_t)
            }
            Element sigma_div_at = sigma.duplicate();
            sigma_div_at.div(a_t);
            Element g_pow_sigma_div_at = g1.duplicate();
            g_pow_sigma_div_at.powZn(sigma_div_at);
            prod.mul(g_pow_sigma_div_at);
            sk1.add(prod);
        }
        Element minus_sigma = sigma.duplicate();
        minus_sigma.mul(-1);
        Element g_minus_sigma = g1.duplicate();
        g_minus_sigma.powZn(minus_sigma);
        Element g_k_DLIN = g_d.get(2).duplicate();
        g_k_DLIN.mul(g_minus_sigma);                    // g^d3 * g^(-σ)
        sk1.add(g_k_DLIN);

        DPVSEngine dpvs = new DPVSEngine();
        Element[][][] Dual = dpvs.sampleRandomDualOrthonormalBases(pairing,g1,g2,N);
        Element[][] g1_c = Dual[0];//g1^c
        Element[][] g2_c = Dual[1];//g2^c*
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        //Element T3 = pairing.pairing(g1_c[0],g2_c[0]).powZn(alpha).getImmutable();
        Element T3 = listPair(g1_c[0],g2_c[0]).powZn(alpha).getImmutable();
        Element[] h3 = g1_c[0];//g1^c1
        Element[] h4 = g1_c[1];//g2^c2
        Element h5 = g1.powZn(
                PairingUtils.MapStringToGroup(pairing,id,PairingUtils.PairingGroupType.Zr)
        ).getImmutable();
        PublicKey pk = new PublicKey(T3,h3,h4,h5);

        Element[] g2_c1 = g2_c[0];//g2^c1*
        Element[] g2_c2 = g2_c[1];//g2^c2*
        SignatureKey sk_th = new SignatureKey(alpha,g2_c1,g2_c2);
        return new UserKey(pk,new SecretKey(sk0,sk_y,sk1,sk_th,A));
    }

    public CipherParameter Encrypt(SecretKey sk,Element m,String accessPolicy,PublicKey pk,String[] A) throws Exception {
        ArrayList<Element> s = new ArrayList<Element>();
        for(int i=0;i<2;i++)
            s.add(pairing.getZr().newRandomElement().getImmutable());
        ArrayList<Element> ct0 = new ArrayList<Element>();
        ct0.add(h1.powZn(s.get(0)).getImmutable());
        ct0.add(h2.powZn(s.get(1)).getImmutable());
        ct0.add(g2.powZn(s.get(0).add(s.get(1))).getImmutable());

        Map<String, int[]> msp = MSP.convert_policy_to_msp(accessPolicy);
        int num_cols = msp.size();//n2

        ArrayList<ArrayList<ArrayList<Element>>> hash_table = new ArrayList<ArrayList<ArrayList<Element>>>();
        for(int j=0;j<num_cols;j++){
            ArrayList<ArrayList<Element>> x = new ArrayList<ArrayList<Element>>();
            String input_for_hash1 = (j+1) + "";
            for(int l=0;l<3;l++){
                ArrayList<Element> y = new ArrayList<Element>();
                String input_for_hash2 = input_for_hash1 + (l+1);
                for(int t=0;t<2;t++){
                    String input_for_hash3 = input_for_hash2 + (t+1);
//                    Element hashsed = PairingUtils.MapStringToGroup(pairing,input_for_hash3,PairingUtils.PairingGroupType.G1);
                    Element hashsed = pairing.getG1().newElement();
                    elementFromString(hashsed,input_for_hash3);
                    y.add(hashsed);
                }
                x.add(y);
            }
            hash_table.add(x);
        }

        String[] Ar = new String[msp.size()];
        int len = 0;

        Map<String, ArrayList<Element>> C = new HashMap<String, ArrayList<Element>>();
        for (Map.Entry<String, int []> entry : msp.entrySet()){
            String attr = entry.getKey();
            Ar[len++] = attr;
            int [] row = entry.getValue();
            ArrayList<Element> ct = new ArrayList<Element>();
            for (int l=0; l<3; l++) {
                Element prod = pairing.getG1().newOneElement();
                int cols = row.length;
                for (int t=0; t<2; t++) {
                    String input_for_hash = attr + (l+1) + (t+1);
//                    Element prod1 = PairingUtils.MapStringToGroup(pairing,input_for_hash,PairingUtils.PairingGroupType.G1);
                    Element prod1 = pairing.getG1().newElement();
                    elementFromString(prod1, input_for_hash);
                    for (int j=0; j<cols; j++) {
                        Element rowj = pairing.getZr().newElement(row[j]);
                        Element hash_table_jlt = hash_table.get(j).get(l).get(t).duplicate();
                        hash_table_jlt.powZn(rowj);
                        prod1.mul(hash_table_jlt);
                    }
                    Element prod_pow_s = prod1.duplicate();
                    prod_pow_s.powZn(s.get(t));
                    prod.mul(prod_pow_s);
                }
                ct.add(prod);
            }
            C.put(attr, ct);
        }

        Element ct1 = T1.powZn(s.get(0)).mul(T2.powZn(s.get(1))).mul(m).getImmutable();
        CipherText CT = new CipherText(ct0,C,ct1,accessPolicy);

        Element r = pairing.getZr().newRandomElement().getImmutable();
        String[] As;
        if(!intersection(A,Ar)){
            throw new Exception("As not satisfy Ar");
        }else {
            As = Ar;
        }

        Date date = new Date();

        String hash_beta = pk.h5.toString() + date.toString() + getCTString(CT) + Arrays.toString(As) + Arrays.toString(Ar);
        Element beta = PairingUtils.MapStringToGroup(pairing,hash_beta,PairingUtils.PairingGroupType.Zr);
        Element[] theta = new Element[N];
        SignatureKey sk_th = sk.sk_th;
        for(int i=0;i<N;i++){
            theta[i] = sk_th.g2_c1[i].powZn(sk_th.alpha.add(r.mul(beta))).mul(sk_th.g2_c2[i].powZn(r.negate())).getImmutable();
        }

        return new CipherParameter(CT,pk,date.toString(),As,Ar,theta,accessPolicy);
    }

    public CipherText Sanitize(CipherParameter CTParameter) throws Exception {
        CipherText CT = CTParameter.ct;
        Element[] theta = CTParameter.theta;
        PublicKey pk = CTParameter.pk;
        CipherText CT1 = new CipherText();

        String hash_beta = pk.h5.toString() + CTParameter.T + getCTString(CT) + Arrays.toString(CTParameter.As) + Arrays.toString(CTParameter.Ar);
        Element beta = PairingUtils.MapStringToGroup(pairing,hash_beta,PairingUtils.PairingGroupType.Zr);
        Element[] g_c1c2 = new Element[N];
        for(int i=0;i<N;i++){
            g_c1c2[i] = pk.h3[i].mul(pk.h4[i].powZn(beta)).getImmutable();
        }
        Element listpair = listPair(g_c1c2,theta);

        if(CTParameter.As.equals(CTParameter.Ar) &&
                listpair.equals(pk.T3)
        ){
            ArrayList<Element> s = new ArrayList<Element>();
            for(int i=0;i<2;i++)
                s.add(pairing.getZr().newRandomElement().getImmutable());

            ArrayList<Element> ct0 = new ArrayList<Element>();
            ct0.add(CT.ct0.get(0).mul(h1.powZn(s.get(0))).getImmutable());
            ct0.add(CT.ct0.get(1).mul(h2.powZn(s.get(1))).getImmutable());
            ct0.add(CT.ct0.get(2).mul(g2.powZn(s.get(0).add(s.get(1)))).getImmutable());

            Map<String, int[]> msp = MSP.convert_policy_to_msp(CTParameter.accessPolicy);
            int num_cols = msp.size();//n2

            ArrayList<ArrayList<ArrayList<Element>>> hash_table = new ArrayList<ArrayList<ArrayList<Element>>>();
            for(int j=0;j<num_cols;j++){
                ArrayList<ArrayList<Element>> x = new ArrayList<ArrayList<Element>>();
                String input_for_hash1 = (j+1) + "";
                for(int l=0;l<3;l++){
                    ArrayList<Element> y = new ArrayList<Element>();
                    String input_for_hash2 = input_for_hash1 + (l+1);
                    for(int t=0;t<2;t++){
                        String input_for_hash3 = input_for_hash2 + (t+1);
//                        Element hashsed = PairingUtils.MapStringToGroup(pairing,input_for_hash3,PairingUtils.PairingGroupType.G1);
                        Element hashsed = pairing.getG1().newElement();
                        elementFromString(hashsed,input_for_hash3);
                        y.add(hashsed);
                    }
                    x.add(y);
                }
                hash_table.add(x);
            }

            Map<String, ArrayList<Element>> C = new HashMap<String, ArrayList<Element>>();
            for (Map.Entry<String, int []> entry : msp.entrySet()){
                String attr = entry.getKey();
                int [] row = entry.getValue();
                ArrayList<Element> ct = new ArrayList<Element>();
                for (int l=0; l<3; l++) {
                    Element prod = pairing.getG1().newOneElement();
                    int cols = row.length;
                    for (int t=0; t<2; t++) {
                        String input_for_hash = attr + (l+1) + (t+1);
//                        Element prod1 = PairingUtils.MapStringToGroup(pairing,input_for_hash,PairingUtils.PairingGroupType.G1);
                        Element prod1 = pairing.getG1().newElement();
                        elementFromString(prod1, input_for_hash);
                        for (int j=0; j<cols; j++) {
                            Element rowj = pairing.getZr().newElement(row[j]);
                            Element hash_table_jlt = hash_table.get(j).get(l).get(t).duplicate();
                            hash_table_jlt.powZn(rowj);
                            prod1.mul(hash_table_jlt);
                        }
                        Element prod_pow_s = prod1.duplicate();
                        prod_pow_s.powZn(s.get(t));
                        prod.mul(prod_pow_s);
                    }
                    ct.add(prod.mul(CT.ct.get(attr).get(l)).getImmutable());
                }
                C.put(attr, ct);
            }

            CT1.ct0 = ct0;
            CT1.ct = C;
            CT1.ct1 = CT.ct1.mul(T1.powZn(s.get(0))).mul(T2.powZn(s.get(1))).getImmutable();
            CT1.accessPolicy = CT.accessPolicy;
        }else{
            throw new Exception("not pass");
        }
        return CT1;
    }

    public Element Decrypt(CipherText CT,SecretKey sk) throws PolicySyntaxException {
        for (String attr : CT.ct.keySet()) {
            if (!sk.sk_y.containsKey(attr)) {
                System.err.println("Policy not satisfied. ("+attr+")");
                System.exit(2);
            }
        }

        Map<String, ArrayList<Element>> ct = CT.ct;
        Map<String, ArrayList<Element>> sk_y = sk.sk_y;

        Element prod1_GT = pairing.getGT().newOneElement();
        Element prod2_GT = pairing.getGT().newOneElement();
        for (int i=0; i<3; i++) {
            Element prod_H = pairing.getG1().newOneElement();
            Element prod_G = pairing.getG1().newOneElement();
            for (String att : ct.keySet()) {
                prod_H.mul(sk_y.get(att).get(i));
                prod_G.mul(ct.get(att).get(i));
            }
            Element kp_prodH = sk.sk_1.get(i).duplicate();
            kp_prodH.mul(prod_H);
            prod1_GT.mul(pairing.pairing(kp_prodH, CT.ct0.get(i)));
            prod2_GT.mul(pairing.pairing(prod_G, sk.sk0.get(i)));
        }
        Element m = CT.ct1.duplicate();
        m.mul(prod2_GT);
        m.div(prod1_GT);

        return m;
    }
}
