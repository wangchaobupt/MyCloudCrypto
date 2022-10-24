package cn.edu.buaa.crypto.encryption.ABACEHAN;

public class CipherParameter {
    public CipherText CT;
    public HeadData Hd;
    public String[] As;
    public CipherParameter(CipherText CT,HeadData Hd,String[] As){
        this.CT = CT;
        this.Hd = Hd;
        this.As = As;
    }
}
