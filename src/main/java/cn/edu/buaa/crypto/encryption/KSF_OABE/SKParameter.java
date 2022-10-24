package cn.edu.buaa.crypto.encryption.KSF_OABE;

public class SKParameter {
    private sk_KGCSPParameter SK_KGCSP;
    private sk_TAParameter SK_TA;
    public SKParameter(sk_KGCSPParameter SK_KGCSP,sk_TAParameter SK_TA){
        this.SK_KGCSP = SK_KGCSP;
        this.SK_TA = SK_TA;
    }

    public sk_KGCSPParameter getSK_KGCSP() {
        return SK_KGCSP;
    }

    public sk_TAParameter getSK_TA() {
        return SK_TA;
    }

    public int getlen(){
        return SK_KGCSP.getlen() + SK_TA.getlen();
    }
}
