package cn.edu.buaa.crypto.encryption.SPACE_part;

import cn.edu.buaa.crypto.encryption.CPSABE.MasterSecretKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SecretKey;

public class MasterKey {
    public MasterSecretKey msk_e;
    public SecretKey sk_s;

    public MasterKey(MasterSecretKey msk_e,SecretKey sk_s){
        this.msk_e = msk_e;
        this.sk_s = sk_s;
    }
}
