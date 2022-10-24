package cn.edu.buaa.crypto.encryption.KPSABE;

public class UserKey {
    public RetrieveKey rk;
    public TransformKey tk;
    public UserKey(TransformKey tk,RetrieveKey rk){
        this.rk = rk;
        this.tk = tk;
    }
}
