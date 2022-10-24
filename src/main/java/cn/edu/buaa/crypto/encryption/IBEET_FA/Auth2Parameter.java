package cn.edu.buaa.crypto.encryption.IBEET_FA;

public class Auth2Parameter {
    private byte[] td;
    public Auth2Parameter(byte[] td){
        this.td = td;
    }

    public byte[] getTd() {
        return td;
    }

    public int getlen(){
        return td.length;
    }
}
