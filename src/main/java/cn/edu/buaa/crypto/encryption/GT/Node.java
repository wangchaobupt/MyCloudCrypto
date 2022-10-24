package cn.edu.buaa.crypto.encryption.GT;

public class Node {
    private double p;// 记录概率
    private char alpha;// 记录对应的字母

    public Node(double p, char alpha) {
        this.p = p;
        this.alpha = alpha;
    }

    public void setp(double p) {
        this.p = p;
    }

    public void setalpha(char a) {
        this.alpha = a;
    }

    public double getp() {
        return p;
    }

    public char getalpha() {
        return alpha;
    }
}

