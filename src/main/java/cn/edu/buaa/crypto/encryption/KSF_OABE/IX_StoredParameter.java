package cn.edu.buaa.crypto.encryption.KSF_OABE;

import edu.princeton.cs.algs4.In;

import java.util.HashMap;
import java.util.Map;

public class IX_StoredParameter {
    private Map<IndexParameter,CipherText> IX_CT;
    public IX_StoredParameter(){
        this.IX_CT = new HashMap<IndexParameter,CipherText>();
    }

    public void getSet(CipherText ct, IndexParameter ix){
        this.IX_CT.put(ix,ct);
    }
    public Map<IndexParameter,CipherText> getIX_CT() {
        return IX_CT;
    }
}
