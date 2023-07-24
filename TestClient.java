
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.event.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.awt.Color;
import java.nio.charset.*;
import java.util.*;
import java.net.*;
import java.io.*;
import java.math.*;
import java.lang.Math.*;
import javax.xml.bind.DatatypeConverter;

public class TestClient extends JFrame implements ActionListener {
    JFrame jf;
    JButton reqbut, verify, decryp;
    static JTextField reqip, emac, mactxt, verific;
    JLabel clienttitle, reqlabel, macad, emaclabel, verificlabel, projecttitle, develop;
    JPanel jp;
    static String ipaddress;
    private static String secretkey;
    private static String saltvalue;
    static Socket socket = null;
    static Socket writesocket = null;
    static Socket socket2 = null;
    static DataInputStream input = null;
    static DataOutputStream output = null;
    static DataOutputStream writeoutput = null;
    static String encrypmac;
    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static Scanner sc;
    static String get;
    static int b, signature, phi;
    static int verification;
    static String encryptedmac;
    private static ObjectOutputStream oos;
    private static PrivateKey clientPrivateKey;

    public TestClient() {
        jf = new JFrame();
        jp = new JPanel();
        projecttitle = new JLabel("SECURE ADDRESS RESOLUTION PROTOCOL");
        develop = new JLabel("DEVELOPED BY S.SHREENATH");
        clienttitle = new JLabel("CLIENT");
        reqip = new JTextField();
        reqbut = new JButton("REQUEST");
        reqlabel = new JLabel("Required IP Address");
        emac = new JTextField();
        emac.setEditable(false);
        verify = new JButton("VERIFY");
        emaclabel = new JLabel("Encrypted MAC Address");
        verific = new JTextField();
        verific.setEditable(false);
        decryp = new JButton("DECRYPT");
        verificlabel = new JLabel("VERIFICATION");
        mactxt = new JTextField();
        mactxt.setEditable(false);
        macad = new JLabel("MAC Address");

        jf.add(projecttitle);
        jf.add(develop);
        jf.add(clienttitle);
        jf.add(reqip);
        jf.add(reqbut);
        jf.add(reqlabel);
        jf.add(emac);
        jf.add(verify);
        jf.add(emaclabel);
        jf.add(verificlabel);
        jf.add(verific);
        jf.add(decryp);
        jf.add(mactxt);
        jf.add(macad);
        jf.add(jp);

        reqbut.addActionListener(this);
        verify.addActionListener(this);
        decryp.addActionListener(this);

        projecttitle.setBounds(200, 20, 500, 70);
        clienttitle.setBounds(300, 70, 100, 80);
        reqip.setBounds(250, 150, 250, 30);
        reqbut.setBounds(400, 200, 190, 30);
        reqlabel.setBounds(100, 150, 190, 30);
        emac.setBounds(250, 250, 250, 30);
        verify.setBounds(400, 300, 180, 30);
        emaclabel.setBounds(80, 250, 180, 40);
        verificlabel.setBounds(120, 350, 180, 40);
        verific.setBounds(250, 360, 250, 30);
        decryp.setBounds(400, 400, 180, 30);
        mactxt.setBounds(250, 460, 250, 30);
        macad.setBounds(120, 455, 180, 40);
        develop.setBounds(250, 500, 250, 100);

        jf.getContentPane().setBackground(Color.YELLOW);
        jf.setVisible(true);
        jf.setSize(700, 700);
        jf.setLayout(null);
        jf.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jf.validate();
    }

    public void actionPerformed(ActionEvent ae) {
        if (ae.getSource() == decryp) {
            String text = emac.getText();
            String decryptedvalue = decrypt(text);
            mactxt.setText(decryptedvalue);
        }
        if (ae.getSource() == reqbut) {
            String ip = reqip.getText();
            ipaddress = ip;
            int port = 5000;
            int port2 = 888;
            try {
                socket = new Socket(ipaddress, port);
                writesocket = new Socket(ipaddress, 3110);
                output = new DataOutputStream(socket.getOutputStream());
                oos = new ObjectOutputStream(writesocket.getOutputStream());
                output.writeUTF(ip);
                socket.close();
                output.close();
                KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
                keyGenRSA.initialize(1024);
                KeyPair keyRSA = keyGenRSA.generateKeyPair();
                clientPrivateKey = keyRSA.getPrivate();
                PublicKey clientPublicKey = keyRSA.getPublic();
                byte[] sign = Create_Digital_Signature(
                        ip.getBytes(),
                        clientPrivateKey);
                oos.writeObject(clientPublicKey);
                oos.writeObject(sign);
                oos.flush();
                oos.close();
                writesocket.close();

                socket2 = new Socket(ipaddress, port2);
                input = new DataInputStream(socket2.getInputStream());
                String line = "";
                while (line.equals("")) {
                    line = input.readUTF();
                    get = line;

                    encryptedmac = line.split(",")[0];
                    secretkey = line.split(",")[1];
                    saltvalue = line.split(",")[2];
                    signature = Integer.parseInt(line.split(",")[3]);
                    b = Integer.parseInt(line.split(",")[4]);
                    phi = Integer.parseInt(line.split(",")[5]);
                    emac.setText(encryptedmac);
                }
                input.close();
                socket2.close();

            } catch (Exception e) {
            }
        }
        if (ae.getSource() == verify) {
            char[] st = encryptedmac.toCharArray();
            int x = st[0];
            int y = st[st.length - 1];
            int msg = x + y;
            boolean check = verifysignature(msg, signature, b, phi);
            if (check) {
                JOptionPane.showMessageDialog(jf, "SIGNATURE VERIFIED");
                verific.setText("Verification Done Succesfully");
            } else {
                JOptionPane.showMessageDialog(jf, "SIGNATURE NOT VERIFIED");
                verific.setText("Verification Unsuccesfull");
            }
        }
    }

    public static byte[] Create_Digital_Signature(
            byte[] input,
            PrivateKey Key)
            throws Exception {
        Signature signature = Signature.getInstance(
                SIGNING_ALGORITHM);
        signature.initSign(Key);
        signature.update(input);
        return signature.sign();
    }

    public static boolean verifysignature(int msg, double sig, int pubkey, int pq) {
        double val = Math.pow(msg, pubkey) % pq;
        if (val == sig) {
            return true;
        }
        return false;

    }

    public static String decrypt(String str) {
        try {
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keyspec = new PBEKeySpec(secretkey.toCharArray(), saltvalue.getBytes(), 65536, 256);
            SecretKey skey = skf.generateSecret(keyspec);
            SecretKeySpec skeyspec = new SecretKeySpec(skey.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeyspec, ivspec);
            return new String(cipher.doFinal(Base64.getDecoder().decode(str)));
        } catch (Exception e) {
            System.out.println("Exception Occured " + e);
        }
        return null;
    }

    public static void main(String[] args) {
        TestClient gui = new TestClient();

    }
}