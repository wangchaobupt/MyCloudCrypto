package cn.edu.buaa.crypto.encryption.AOACE;

public class UserKey {
    public RetrieveKey rk;
    public TransformKey tk;
    public UserKey(RetrieveKey rk,TransformKey tk){
        this.rk = rk;
        this.tk = tk;
    }
}
