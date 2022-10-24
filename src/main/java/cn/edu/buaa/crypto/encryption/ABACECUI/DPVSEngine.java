package cn.edu.buaa.crypto.encryption.ABACECUI;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

public class DPVSEngine {
    public Element[][][] sampleRandomDualOrthonormalBases(Pairing pairing, Element g1, Element g2,int N) {
        Element[][] canonicalBase = new Element[N][N];

        for(int i = 0; i < N; ++i) {
            for(int j=0;j<N;++j){
                if(i==j)
                    canonicalBase[i][j] = g1;
                else
                    canonicalBase[i][j] = pairing.getG1().newOneElement();
            }
        }

        Element[][] canonicalBase1 = new Element[N][N];

        for(int i = 0; i < N; ++i) {
            for(int j=0;j<N;++j){
                if(i==j)
                    canonicalBase1[i][j] = g2;
                else
                    canonicalBase1[i][j] = pairing.getG2().newOneElement();
            }
        }

        Element[][] linearTransformation = sampleUniformTransformation(pairing.getZr(), N);
        Element[][] B = new Element[N][N];

        for(int i=0;i<N;i++){
            for(int k=0;k<N;k++){
                B[i][k] = canonicalBase[0][k].powZn(linearTransformation[i][0]).getImmutable();
                for(int j=1;j<N;j++){
                    B[i][k] = B[i][k].add(canonicalBase[j][k].powZn(linearTransformation[i][j])).getImmutable();
                }
            }
        }

        linearTransformation = invert(ElementUtils.transpose(linearTransformation));
        Element[][] Bs = new Element[N][N];

        for(int i=0;i<N;i++){
            for(int k=0;k<N;k++){
                Bs[i][k] = canonicalBase1[0][k].powZn(linearTransformation[i][0]).getImmutable();
                for(int j=1;j<N;j++){
                    Bs[i][k] = Bs[i][k].add(canonicalBase1[j][k].powZn(linearTransformation[i][j])).getImmutable();
                }
            }
        }

        return new Element[][][]{B, Bs};
    }

    public static Element[][] sampleUniformTransformation(Field field, int n) {
        Element[][] matrix = new Element[n][n];

        for(int i = 0; i < n; ++i) {
            for(int j = 0; j < n; ++j) {
                matrix[i][j] = field.newRandomElement();
            }
        }

        return matrix;
    }

    public static Element[][] invert(Element[][] matrix) {
        int n = matrix.length;
        Element[][] tempArray = new Element[n][2 * n];
        Element[][] result = new Element[n][n];
        ElementUtils.copyArray(tempArray, matrix, n, n, 0, 0);
        tempArray = invertArray(tempArray, n);
        ElementUtils.copyArray(result, tempArray, n, 2 * n, 0, n);
        return result;
    }

    public static Element[][] invertArray(Element[][] D, int n) {
        Field field = D[0][0].getField();

        int n2;
        int i;
        for(n2 = 0; n2 < n; ++n2) {
            for(i = 0; i < n; ++i) {
                D[n2][i + n] = field.newZeroElement();
            }

            D[n2][n2 + n] = field.newOneElement();
        }

        n2 = 2 * n;

        for(i = 0; i < n; ++i) {
            Element alpha = D[i][i].duplicate();
            if (alpha.isZero()) {
                throw new IllegalArgumentException("Singular matrix, cannot invert");
            }

            int k;
            for(k = 0; k < n2; ++k) {
                D[i][k].div(alpha);
            }

            for(k = 0; k < n; ++k) {
                if (k - i != 0) {
                    Element beta = D[k][i].duplicate();

                    for(int j = 0; j < n2; ++j) {
                        D[k][j].sub(beta.duplicate().mul(D[i][j]));
                    }
                }
            }
        }

        return D;
    }

}
