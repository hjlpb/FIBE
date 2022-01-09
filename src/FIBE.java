import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

public class FIBE {

    public static void setup(String pairingParametersFileName, int U, int d, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();

        Properties mskProp = new Properties();
        Properties pkProp = new Properties();
        //属性表示为1，2，3，...，U
        //对每个属性i，选取一个随机数ti作为该属性对应的主密钥，并计算相应公钥g^ti
        for (int i = 1; i <= U; i++){
            Element t = bp.getZr().newRandomElement().getImmutable();
            Element T = g.powZn(t).getImmutable();
            mskProp.setProperty("t"+i, Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
            pkProp.setProperty("T"+i, Base64.getEncoder().withoutPadding().encodeToString(T.toBytes()));
        }
        //另外选取一个随机数y，计算e(g,g)^y
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element egg_y = bp.pairing(g, g).powZn(y).getImmutable();
        mskProp.setProperty("y", Base64.getEncoder().withoutPadding().encodeToString(y.toBytes()));
        pkProp.setProperty("egg_y", Base64.getEncoder().withoutPadding().encodeToString(egg_y.toBytes()));
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        //注意区分数据类型。上面写的数据类型群元素，因此使用了Base64编码。
        //d在实际应用中定义为一个int类型，直接用Integer.toString方法转字符串
        pkProp.setProperty("d", Integer.toString(d));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String dString = pkProp.getProperty("d");
        int d = Integer.parseInt(dString);

        Properties mskProp = loadPropFromFile(mskFileName);
        String yString = mskProp.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yString)).getImmutable();

        //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
        //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
        //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=y。
        Element[] coef = new Element[d];
        coef[0] = y;
        for (int i = 1; i < d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }

        Properties skProp = new Properties();
        //计算每个属性对应的私钥g^(q/t)，q是多项式在该属性位置的值，t是属性对应的主密钥
        for (int att : userAttList) {
            String tString = mskProp.getProperty("t"+att);
            Element t = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
            Element q = qx(bp.getZr().newElement(att), coef, bp.getZr()).getImmutable();
            Element D = g.powZn(q.div(t)).getImmutable();

            skProp.setProperty("D"+att, Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        }
        //将用户属性列表也添加在私钥中
        skProp.setProperty("userAttList", Arrays.toString(userAttList));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element message, int[] messageAttList, String pkFileName, String ctFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String eggString = pkProp.getProperty("egg_y");
        Element egg_y = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(eggString)).getImmutable();
        //计算密文组件 EP=Me(g,g)^(ys)
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element EP = message.duplicate().mul(egg_y.powZn(s)).getImmutable();

        Properties ctProp = new Properties();
        //针对每个密文属性，计算密文组件 E=T^s
        for (int att : messageAttList) {
            String TString = pkProp.getProperty("T"+att);
            Element T = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TString)).getImmutable();
            Element E = T.powZn(s).getImmutable();

            ctProp.setProperty("E"+att, Base64.getEncoder().withoutPadding().encodeToString(E.toBytes()));
        }
        ctProp.setProperty("EP", Base64.getEncoder().withoutPadding().encodeToString(EP.toBytes()));
        //密文属性列表也添加至密文中
        ctProp.setProperty("messageAttList", Arrays.toString(messageAttList));
        storePropToFile(ctProp, ctFileName);
    }

    public static Element decrypt(String pairingParametersFileName, String pkFileName, String ctFileName, String skFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String dString = pkProp.getProperty("d");
        int d = Integer.parseInt(dString);

        Properties ctProp = loadPropFromFile(ctFileName);
        String messageAttListString = ctProp.getProperty("messageAttList");
        //恢复明文消息的属性列表 int[]类型
        int[] messageAttList = Arrays.stream(messageAttListString.substring(1, messageAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        Properties skProp = loadPropFromFile(skFileName);
        String userAttListString = skProp.getProperty("userAttList");
        //恢复用户属性列表 int[]类型
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        //判断两个列表重合个数是否小于d
        int[] intersectionAttList = intersection(messageAttList, userAttList);
        System.out.println("重合属性列表：" + Arrays.toString(intersectionAttList));
        System.out.println("重合属性个数为：" + intersectionAttList.length);
        if (intersectionAttList.length < d) {
            System.out.println("不满足解密门限，无法解密！");
            return null;
        }
        //从两个列表中的重合项中取前d项，构成解密属性列表
        int[] decAttList = Arrays.copyOfRange(intersectionAttList, 0, d);
        System.out.println("解密所用属性列表：" + Arrays.toString(decAttList));

        Element denominator = bp.getGT().newOneElement().getImmutable();
        //针对解密属性列表中的每个属性，计算e(D,E)^delta，并将结果连乘
        for (int att : decAttList){
            String EString = ctProp.getProperty("E"+att);
            Element E = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(EString)).getImmutable();

            String DString = skProp.getProperty("D"+att);
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();

            //计算属性对应的拉格朗日因子，作为指数。目标值x为0。
            Element delta = lagrange(att, decAttList, 0, bp.getZr()).getImmutable();
            denominator = denominator.mul(bp.pairing(E,D).powZn(delta));
        }

        String EPString = ctProp.getProperty("EP");
        Element EP = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(EPString)).getImmutable();
        //恢复M=EP除以上述连乘结果
        Element res = EP.div(denominator);
        return res;
    }

    //计算由coef为系数确定的多项式qx在点x处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element x, Element[] coef, Field Zr){
        Element res = coef[0];
        for (int i = 1; i < coef.length; i++){
            Element exp = Zr.newElement(i).getImmutable();
            //x一定要使用duplicate复制使用，因为x在每一次循环中都要使用，如果不加duplicte，x的值会发生变化
            res = res.add(coef[i].mul(x.duplicate().powZn(exp)));
        }
        return res;
    }

    //求两个数组的交集
    public static int[] intersection(int[] nums1, int[] nums2) {
        Arrays.sort(nums1);
        Arrays.sort(nums2);
        int length1 = nums1.length, length2 = nums2.length;
        int[] intersection = new int[length1 + length2];
        int index = 0, index1 = 0, index2 = 0;
        while (index1 < length1 && index2 < length2) {
            int num1 = nums1[index1], num2 = nums2[index2];
            if (num1 == num2) {
                // 保证加入元素的唯一性
                if (index == 0 || num1 != intersection[index - 1]) {
                    intersection[index++] = num1;
                }
                index1++;
                index2++;
            } else if (num1 < num2) {
                index1++;
            } else {
                index2++;
            }
        }
        return Arrays.copyOfRange(intersection, 0, index);
    }

    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x, Field Zr) {
        Element res = Zr.newOneElement().getImmutable();
        Element iElement = Zr.newElement(i).getImmutable();
        Element xElement = Zr.newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(Zr.newElement(j));
                Element denominator = iElement.sub(Zr.newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }


    public static void main(String[] args) throws Exception {
        int U = 20;
        int d = 5;
        System.out.println("系统解密门限为：" + d);

        int[] userAttList = {1, 5, 3, 6, 10, 11};
        int[] messageAttList = {1,  3,  5,  7, 9, 10, 11};

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, U, d, pkFileName, mskFileName);

        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

        Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("明文消息:" + message);
        encrypt(pairingParametersFileName, message, messageAttList, pkFileName, ctFileName);

        Element res = decrypt(pairingParametersFileName, pkFileName, ctFileName, skFileName);
        System.out.println("解密结果:" + res);
        if (message.isEqual(res)) {
            System.out.println("成功解密！");
        }
    }

}
