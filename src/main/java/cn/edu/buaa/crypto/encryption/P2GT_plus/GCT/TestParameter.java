package cn.edu.buaa.crypto.encryption.P2GT_plus.GCT;

public class TestParameter {
    private int[] rs;
    private byte[][] pID;
    public TestParameter(int[] rs,byte[][] pid){
        this.rs = rs;
        this.pID = pid;
    }

    public int[] getRs() {
        return rs;
    }

    public byte[][] getpID() {
        return pID;
    }

    public int getlen(){
        int len = rs.length*4;
        for(int i=0;i<pID.length;i++){
            len += pID[i].length;
        }
        return len;
    }
}
