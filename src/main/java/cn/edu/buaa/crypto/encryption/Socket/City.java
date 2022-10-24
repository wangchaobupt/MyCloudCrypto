package cn.edu.buaa.crypto.encryption.Socket;

import java.io.Serializable;
import java.util.List;

public class City implements Serializable {

    //实体类，特别注意，作为对象数据流传输，需要继承java.io.Serializable，使用对象进行序列化

    private List cityList;

    public List getCityList() {
        return cityList;
    }

    public void setCityList(List cityList) {
        this.cityList = cityList;
    }
}

