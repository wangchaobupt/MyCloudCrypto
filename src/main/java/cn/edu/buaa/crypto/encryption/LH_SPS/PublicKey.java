package cn.edu.buaa.crypto.encryption.LH_SPS;
import it.unisa.dia.gas.jpbc.Element;

public class PublicKey {
    public Element gz,gr,h,hz;
    public Element[] w,gi,hi;
    public PublicKey(Element gz,Element gr,Element h,Element hz,
                     Element[] gi,Element[] hi,Element[] w){
        this.gi = gi;
        this.hi = hi;
        this.h = h;
        this.hz = hz;
        this.gr = gr;
        this.gz = gz;
        this.w = w;
    }
}
