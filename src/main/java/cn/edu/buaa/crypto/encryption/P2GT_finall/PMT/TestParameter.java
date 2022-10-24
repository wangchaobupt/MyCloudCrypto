package cn.edu.buaa.crypto.encryption.P2GT_finall.PMT;

import it.unisa.dia.gas.jpbc.Element;

public class TestParameter {
    private int[] rs;
    private byte[][] pID;
    public TestParameter(int[] rs, byte[][] pid){
        this.rs = rs;
        this.pID = pid;
    }

    public byte[][] getpID() {
        return pID;
    }

    public int[] getRs() {
        return rs;
    }

    public int getlen(){
        int len = rs.length*4;
        for(int i=0;i<pID.length;i++){
            len += pID[i].length;
        }
        return len;
    }
}
