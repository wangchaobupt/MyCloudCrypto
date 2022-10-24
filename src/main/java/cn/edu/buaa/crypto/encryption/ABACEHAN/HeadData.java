package cn.edu.buaa.crypto.encryption.ABACEHAN;

import it.unisa.dia.gas.jpbc.Element;

public class HeadData {
    public Element K,L1,L2,L3,R1,R2,R3,R4,R5,R6;
    public HeadData(Element k,Element l1,Element l2,Element l3,Element r1,Element r2,Element r3,Element r4,Element r5,Element r6){
        K = k;
        L1 = l1;
        L2 = l2;
        L3 = l3;
        R1 = r1;
        R2 = r2;
        R3 = r3;
        R4 = r4;
        R5 = r5;
        R6 = r6;
    }
}
