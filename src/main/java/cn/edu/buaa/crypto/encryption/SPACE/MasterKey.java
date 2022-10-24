package cn.edu.buaa.crypto.encryption.SPACE;

import cn.edu.buaa.crypto.encryption.CPSABE.MasterSecretKey;
import cn.edu.buaa.crypto.encryption.LH_SPS.SecretKey;

public class MasterKey {
    public MasterSecretKey msk_e;
    public cn.edu.buaa.crypto.encryption.ABS.MasterSecretKey msk_s;
    public SecretKey sk_s;

    public MasterKey(MasterSecretKey msk_e,cn.edu.buaa.crypto.encryption.ABS.MasterSecretKey msk_s,SecretKey sk_s){
        this.msk_e = msk_e;
        this.msk_s = msk_s;
        this.sk_s = sk_s;
    }
}
