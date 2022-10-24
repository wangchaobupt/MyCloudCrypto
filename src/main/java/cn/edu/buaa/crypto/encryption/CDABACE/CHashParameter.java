package cn.edu.buaa.crypto.encryption.CDABACE;
import it.unisa.dia.gas.jpbc.Element;

import java.util.Map;

public class CHashParameter {
    int size;
    public byte[][] Cbytes;
    CipherData ct;
    Element X1, X2;
    Map<String, Element> X3s, X4s, E0s, E1s, E2s, E3s;

    public CHashParameter(CipherData ct, Element X1, Element X2, Map<String, Element> X3s, Map<String, Element> X4s, Map<String, Element> E0s, Map<String, Element> E1s, Map<String, Element> E2s, Map<String, Element> E3s) {
        size = 2 + ct.Cs.size() * 2 + 2 + X3s.size() * 6;
        Cbytes = new byte[size][];
        Cbytes[0] = ct.C.toBytes();
        Cbytes[1] = ct.CPrime.toBytes();

        int j = 2;
        for (String rho : ct.Cs.keySet()) {
            Cbytes[j] = ct.Cs.get(rho).toBytes();
            j++;
        }
        for (String rho : ct.Ds.keySet()) {
            Cbytes[j] = ct.Ds.get(rho).toBytes();
            j++;
        }
        Cbytes[j] = X1.toBytes();
        j++;
        Cbytes[j] = X2.toBytes();
        j++;

        for (String rho : X3s.keySet()) {
            Cbytes[j] = X3s.get(rho).toBytes();
            j++;
        }
        for (String rho : X4s.keySet()) {
            Cbytes[j] = X4s.get(rho).toBytes();
            j++;
        }
        for (String rho : E0s.keySet()) {
            Cbytes[j] = E0s.get(rho).toBytes();
            j++;
        }
        for (String rho : E1s.keySet()) {
            Cbytes[j] = E1s.get(rho).toBytes();
            j++;
        }
        for (String rho : E2s.keySet()) {
            Cbytes[j] = E2s.get(rho).toBytes();
            j++;
        }
        for (String rho : E3s.keySet()) {
            Cbytes[j] = E3s.get(rho).toBytes();
            j++;
        }

    }

    public int getlen() {
        int len = Cbytes[0].length;
        for (int i = 1; i < Cbytes.length; i++) {
            len += Cbytes[i].length;
        }
        return len;
    }

    public byte[] getCbytes() {
        int len = getlen();

        byte[] res = new byte[len];
        int strat = 0;
        for (int i = 0; i < size; i++) {
            System.arraycopy(Cbytes[i], 0, res, strat, Cbytes[i].length);
            strat += Cbytes[i].length;
        }
        return res;
    }

}
