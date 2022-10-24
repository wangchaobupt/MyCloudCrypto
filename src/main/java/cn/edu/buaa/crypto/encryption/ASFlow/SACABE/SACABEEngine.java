package cn.edu.buaa.crypto.encryption.ASFlow.SACABE;

import cn.edu.buaa.crypto.encryption.ABACECUI.MSP;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class SACABEEngine {
    private static SACABEEngine engine;
    private Pairing pairing;
    private Element g,h,h1,h2,T1,T2;
    private Element s1,s2;

    public static SACABEEngine getInstance(){
        if(engine == null){
            engine = new SACABEEngine();
        }
        return engine;
    }

    public Pairing getPairing() {return this.pairing;}

    public MasterPublicKey getMPK(){
        return new MasterPublicKey(g,h,h1,h2,T1,T2);
    }

    public Element getS1(){
        return s1;
    }
    public Element getS2(){
        return s2;
    }
    public static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    public MasterSecretKey Setup(String perperties){
        this.pairing = PairingFactory.getPairing(perperties);
        g = pairing.getG1().newRandomElement().getImmutable();
        h = pairing.getG2().newRandomElement().getImmutable();
        ArrayList<Element> a = new ArrayList<Element>();
        ArrayList<Element> b = new ArrayList<Element>();
        ArrayList<Element> d = new ArrayList<Element>();
        ArrayList<Element> g_d = new ArrayList<Element>();
        for(int i=0;i<2;i++){
            a.add(pairing.getZr().newRandomElement().getImmutable());
            b.add(pairing.getZr().newRandomElement().getImmutable());
            d.add(pairing.getZr().newRandomElement().getImmutable());
            g_d.add(g.powZn(d.get(i)).getImmutable());
        }
        d.add(pairing.getZr().newRandomElement().getImmutable());
        g_d.add(g.powZn(d.get(2)).getImmutable());

        h1 = h.powZn(a.get(0)).getImmutable();
        h2 = h.powZn(a.get(1)).getImmutable();
        T1 = pairing.pairing(g,h).powZn(d.get(0).mul(a.get(0)).add(d.get(2))).getImmutable();
        T2 = pairing.pairing(g,h).powZn(d.get(1).mul(a.get(1)).add(d.get(2))).getImmutable();
        return new MasterSecretKey(a,b,g_d);
    }

    public SecretKey KeyGen(MasterSecretKey msk,String[] R) throws NoSuchAlgorithmException {
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
            sk0.add(h.powZn(br.get(i)).getImmutable());
        }

        Map<String, ArrayList<Element>> sk_y = new HashMap<String, ArrayList<Element>>();
        ArrayList<Element> a = msk.a;

        for (String attr: R) {
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
                Element g_sigma_attr_at = g.duplicate();
                g_sigma_attr_at.powZn(sigma_attr_at);           // g ^ (σ'/a_t)
                prod.mul(g_sigma_attr_at);                      // prod *= (g ^ (σ'/a_t))
                key.add(prod);
            }
            Element minus_sigma_attr = sigma_attr.duplicate();
            minus_sigma_attr.mul(-1);                           // -σ
            key.add(g.duplicate().powZn(minus_sigma_attr));     // g ^ (-σ)
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
            Element g_pow_sigma_div_at = g.duplicate();
            g_pow_sigma_div_at.powZn(sigma_div_at);
            prod.mul(g_pow_sigma_div_at);
            sk1.add(prod);
        }
        Element minus_sigma = sigma.duplicate();
        minus_sigma.mul(-1);
        Element g_minus_sigma = g.duplicate();
        g_minus_sigma.powZn(minus_sigma);
        Element g_k_DLIN = g_d.get(2).duplicate();
        g_k_DLIN.mul(g_minus_sigma);                    // g^d3 * g^(-σ)
        sk1.add(g_k_DLIN);

        return new SecretKey(sk0,sk1,sk_y);
    }

    public CipherText Encrypt(Element m,String accessPolicy) throws NoSuchAlgorithmException {
        ArrayList<Element> s = new ArrayList<Element>();
        for(int i=0;i<2;i++)
            s.add(pairing.getZr().newRandomElement().getImmutable());
        s1 = s.get(0);
        s2 = s.get(1);
        ArrayList<Element> ct0 = new ArrayList<Element>();
        ct0.add(h1.powZn(s.get(0)).getImmutable());
        ct0.add(h2.powZn(s.get(1)).getImmutable());
        ct0.add(h.powZn(s.get(0).add(s.get(1))).getImmutable());

        Map<String, int[]> msp = MSP.convert_policy_to_msp(accessPolicy);
        int num_cols = msp.size();
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

        Map<String, ArrayList<Element>> ct1 = new HashMap<String, ArrayList<Element>>();
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
            ct1.put(attr, ct);
        }

        Element C = T1.powZn(s.get(0)).mul(T2.powZn(s.get(1))).mul(m).getImmutable();
        return new CipherText(accessPolicy,ct0,ct1,C);
    }

    public CipherText Sanitize(CipherText CT) throws NoSuchAlgorithmException {
        ArrayList<Element> s = new ArrayList<Element>();
        for(int i=0;i<2;i++)
            s.add(pairing.getZr().newRandomElement().getImmutable());

        ArrayList<Element> ct0 = new ArrayList<Element>();
        ct0.add(CT.ct0.get(0).mul(h1.powZn(s.get(0))).getImmutable());
        ct0.add(CT.ct0.get(1).mul(h2.powZn(s.get(1))).getImmutable());
        ct0.add(CT.ct0.get(2).mul(h.powZn(s.get(0).add(s.get(1)))).getImmutable());

        Map<String, int[]> msp = MSP.convert_policy_to_msp(CT.accessPolicy);
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

        Map<String, ArrayList<Element>> ct1 = new HashMap<String, ArrayList<Element>>();
        for (Map.Entry<String, int []> entry : msp.entrySet()){
            String attr = entry.getKey();
            int [] row = entry.getValue();
            ArrayList<Element> ct = new ArrayList<Element>();
            for (int l=0; l<3; l++) {
                Element prod = pairing.getG1().newOneElement();
                int cols = row.length;
                for (int t=0; t<2; t++) {
                    String input_for_hash = attr + (l+1) + (t+1);
                    //                       Element prod1 = PairingUtils.MapStringToGroup(pairing,input_for_hash,PairingUtils.PairingGroupType.G1);
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
            ct1.put(attr, ct);
        }
        Element C = CT.C.mul(T1.powZn(s.get(0))).mul(T2.powZn(s.get(1))).getImmutable();
        return new CipherText(CT.accessPolicy,ct0,ct1,C);
    }

    public Element Decrypt(CipherText CT,SecretKey sk){
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
        Element m = CT.C.duplicate();
        m.mul(prod2_GT);
        m.div(prod1_GT);

        return m;
    }
}
