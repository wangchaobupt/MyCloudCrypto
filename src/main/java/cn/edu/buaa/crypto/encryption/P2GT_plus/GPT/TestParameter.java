package cn.edu.buaa.crypto.encryption.P2GT_plus.GPT;

public class TestParameter {
    private int[] rs;
    public TestParameter(int[] rs){
        this.rs = rs;
    }

    public int[] getRs() {
        return rs;
    }

    public int getlen(){
        return rs.length*4;
    }
}
