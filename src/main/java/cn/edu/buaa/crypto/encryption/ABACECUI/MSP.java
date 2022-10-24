package cn.edu.buaa.crypto.encryption.ABACECUI;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class MSP {
/*
    private static final int [][] M1 = {
            {1}};

    private static final int [][] M2 = {
            {1,  1},
            {0, -1}};

    private static final int [][] M3 = {
            {1,  1,  0},
            {0, -1,  1},
            {0,  0, -1}};

    private static final int [][] M4 = {
            {1,  1,  0,  0},
            {0, -1,  1,  0},
            {0,  0, -1,  1},
            {0,  0,  0, -1}};

    private static final int [][] M5 = {
            {1,  1,  0,  0,  0},
            {0, -1,  1,  0,  0},
            {0,  0, -1,  1,  0},
            {0,  0,  0, -1,  1},
            {0,  0,  0,  0, -1}};

    private static final int [][] M6 = {
            {1,  1,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0},
            {0,  0, -1,  1,  0,  0},
            {0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0, -1}};

    private static final int [][] M7 = {
            {1,  1,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M8 = {
            {1,  1,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M9 = {
            {1,  1,  0,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][] M10 = {
            {1,  1,  0,  0,  0,  0,  0,  0,  0,  0},
            {0, -1,  1,  0,  0,  0,  0,  0,  0,  0},
            {0,  0, -1,  1,  0,  0,  0,  0,  0,  0},
            {0,  0,  0, -1,  1,  0,  0,  0,  0,  0},
            {0,  0,  0,  0, -1,  1,  0,  0,  0,  0},
            {0,  0,  0,  0,  0, -1,  1,  0,  0,  0},
            {0,  0,  0,  0,  0,  0, -1,  1,  0,  0},
            {0,  0,  0,  0,  0,  0,  0, -1,  1,  0},
            {0,  0,  0,  0,  0,  0,  0,  0, -1,  1},
            {0,  0,  0,  0,  0,  0,  0,  0,  0, -1}};

    private static final int [][][] cheatyMSPs =
            {null, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10};


    // convert policy string to msp
    // FIXME: Hard-coded to support AND operations only
    public static Map<String, int[]> convert_policy_to_msp(String policy) {
        String [] attrs = policy.split(" and ");
        if (attrs.length > 10 || attrs.length < 1) {
            System.err.println("MSP conversion error!");
            System.exit(1);
        }
        Map<String, int[]> msp = new HashMap<String, int[]>();
        for (int i=0; i<attrs.length; i++) {
            //System.out.println("\""+attrs[i]+ "\" -> " + Arrays.toString(cheatyMSPs[attrs.length][i]));
            msp.put(attrs[i], cheatyMSPs[attrs.length][i]);
        }
        return msp;
    }

 */

//    public static int[][] creatMSP(int N){
//        int[][] M = new int[N][N];
//        for(int i=0;i<N;i++){
//            for(int j=0;j<N;j++){
//                if(i==j){
//                    if(i==0)
//                        M[i][j] = 1;
//                    else
//                        M[i][j] = -1;
//                }else if(j == i+1){
//                    M[i][j] = 1;
//                }
//            }
//        }
//        return M;
//    }

    public static int[][] creatMSP(int N){
        int[][] M = new int[N][N];
        for(int i=0;i<N;i++){
            for(int j=0;j<N;j++){
                if(i==j){
                    if(i==0)
                        M[i][j] = 1;
                    else
                        M[i][j] = -1;
                }else if(j==i+1){
                    M[i][j] = 1;
                }
            }
        }
        return M;
    }

    public static Map<String, int[]> convert_policy_to_msp(String policy) {
        String [] attrs = policy.split(" and ");
        int[][] M = creatMSP(attrs.length);
        Map<String, int[]> msp = new HashMap<String, int[]>();
        for (int i=0; i<attrs.length; i++) {
            msp.put(attrs[i], M[i]);
        }
        return msp;
    }

    public static void main(String[] args) {
//        String policy = "";
//        for(int i=0;i<9;i++){
//            policy += String.valueOf(i) + " and ";
//        }
//        policy += String.valueOf(9);
        int[][] msp = creatMSP(9);
        for(int i=0;i<msp.length;i++){
            System.out.println(Arrays.toString(msp[i]));
        }
    }

}
