package cn.edu.buaa.crypto.encryption.KSF_OABE;

import it.unisa.dia.gas.jpbc.Element;

import java.util.HashMap;
import java.util.Map;

public class TA_StoredParameter {
    Map<String,SKParameter> ta;//A+SK
    private ok_TAParameter OK_TA;

    public TA_StoredParameter(ok_TAParameter OK_TA){
        this.OK_TA = OK_TA;
        this.ta = new HashMap<String, SKParameter>();
    }

    public void SetTA(String accessPolicy, SKParameter sk){
        this.ta.put(accessPolicy,sk);
    }

    public Map<String, SKParameter> getTa() {
        return ta;
    }

    public ok_TAParameter getOK_TA() {
        return OK_TA;
    }
}
