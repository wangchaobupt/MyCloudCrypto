package cn.edu.buaa.crypto.encryption.Socket;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.*;

public class Client {
    public static void main(String[] arg) throws Exception {
        //封装一个对象实例

        Pairing pairing = PairingFactory.getPairing("params/SS768.properties");
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Map<String, Element> Cs1 = new HashMap<String, Element>();
        Element[] c = new Element[2];
        System.out.println("c:");
        for(int i=0;i<2;i++){
            c[i] = pairing.getG1().newRandomElement().getImmutable();
            Cs1.put(String.valueOf(i),c[i]);
            System.out.println(i+" : "+c[i]);
        }

        Flist flist = new Flist(g,Cs1);
        //连接到服务器端
        Socket socketConnection = new Socket(InetAddress.getLocalHost(), 6688);
        //使用ObjectOutputStream和ObjectInputStream进行对象数据传输
        ObjectOutputStream out = new ObjectOutputStream(socketConnection.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socketConnection.getInputStream());
        //将客户端的对象数据流输出到服务器端去
        out.writeObject(flist);
        out.flush();
        //读取服务器端返回的对象数据流
//        City cityBack = (City) in.readObject();
//        List backList = cityBack.getCityList();
//        for (int i = 0; i < backList.size(); i++) {
//            System.out.println("客户端得到返回城市数据：" + backList.get(i).toString());
//        }
        out.close();
        in.close();


    }
}
