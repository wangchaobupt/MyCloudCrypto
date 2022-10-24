package cn.edu.buaa.crypto.encryption.KSF_OABE;

public class initParameter {
    private ok_KGCSPParameter OK_KGCSP;
    private ok_TAParameter OK_TA;
    public initParameter(ok_KGCSPParameter k1, ok_TAParameter k2){
        this.OK_KGCSP = k1;
        this.OK_TA = k2;
    }

    public ok_KGCSPParameter getOK_KGCSP() {
        return OK_KGCSP;
    }

    public ok_TAParameter getOK_TA() {
        return OK_TA;
    }

    public int getlen(){
        return OK_TA.getX().toBytes().length + OK_KGCSP.getX().toBytes().length;
    }
}
