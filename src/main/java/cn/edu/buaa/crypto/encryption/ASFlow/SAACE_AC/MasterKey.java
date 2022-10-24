package cn.edu.buaa.crypto.encryption.ASFlow.SAACE_AC;

import cn.edu.buaa.crypto.encryption.ASFlow.AA_EQS.SecretKey;
import cn.edu.buaa.crypto.encryption.ASFlow.AGHO_SPS.SigningKey;
import cn.edu.buaa.crypto.encryption.ASFlow.SACABE.MasterSecretKey;

public class MasterKey {
    public MasterSecretKey msk;
    public SecretKey esk;
    public cn.edu.buaa.crypto.encryption.ASFlow.TABS.MasterSecretKey ask;
    public SigningKey ssk;

    public MasterKey(MasterSecretKey msk, SecretKey esk, cn.edu.buaa.crypto.encryption.ASFlow.TABS.MasterSecretKey ask, SigningKey ssk) {
        this.msk = msk;
        this.esk = esk;
        this.ask = ask;
        this.ssk = ssk;
    }
}
