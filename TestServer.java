
import javax.swing.*;

import javafx.scene.text.Font;
import java.awt.*;
import java.awt.Color;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.nio.charset.*;
import java.util.Base64;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.math.*;
import java.lang.Math.*;

public class TestServer extends JFrame implements ActionListener {
    JButton getmac, encryp, send;
    static JFrame jf;
    JPanel jp;
    JLabel servertitle, reqtiplab, reqmac, emaclab, projtitle, develop;
    static ServerSocket ss;
    static ServerSocket ss2;
    static ServerSocket ss3;
    static Socket readsocket;
    static Socket s;
    static Socket socket;
    static DataInputStream din;
    static DataOutputStream dout;
    static DataInputStream readinput;
    static JTextField reqtip, macreq, emac;
    private static String secretkey;
    private static String saltvalue;
    static String ipaddress;
    static String encryptedval;
    static int p = 11;
    static int q = 17;
    static int n = p * q;
    static int phi = 160;
    static int a, b;
    static double signature;
    static byte[] sign2, message;
    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static ObjectInputStream ois;
    private static PrivateKey serverPrivateKey;
    private static PublicKey serverPublicKey, clientPublicKey;

    TestServer() {

        jf = new JFrame();
        jp = new JPanel();
        servertitle = new JLabel("SERVER");
        reqtip = new JTextField();
        reqtiplab = new JLabel("IP Address");
        getmac = new JButton("GET MAC");
        reqmac = new JLabel("Required MAC Address");
        macreq = new JTextField();
        encryp = new JButton("ENCRYPT");
        emaclab = new JLabel("Encrypted MAC Address");
        emac = new JTextField();
        send = new JButton("SEND");
        projtitle = new JLabel("SECURE ADDRESS RESOLUTION PROTOCOL");
        develop = new JLabel("DEVELOPED BY S.SHREENATH");

        reqtip.setEditable(false);
        macreq.setEditable(false);
        emac.setEditable(false);
        jf.add(servertitle);
        jf.add(reqtip);
        jf.add(reqtiplab);
        jf.add(getmac);
        jf.add(reqmac);
        jf.add(macreq);
        jf.add(encryp);
        jf.add(emaclab);
        jf.add(emac);
        jf.add(send);
        jf.add(projtitle);
        jf.add(develop);
        jf.add(jp);

        getmac.addActionListener(this);
        encryp.addActionListener(this);
        send.addActionListener(this);

        projtitle.setBounds(200, 20, 500, 70);
        servertitle.setBounds(300, 70, 100, 80);
        reqtip.setBounds(250, 150, 250, 30);
        getmac.setBounds(400, 200, 190, 30);
        reqtiplab.setBounds(150, 150, 190, 30);
        macreq.setBounds(250, 250, 250, 30);
        encryp.setBounds(400, 300, 180, 30);
        reqmac.setBounds(80, 250, 180, 40);
        emac.setBounds(250, 360, 250, 30);
        emaclab.setBounds(80, 350, 180, 40);
        send.setBounds(400, 400, 180, 30);
        develop.setBounds(250, 500, 250, 100);

        jf.getContentPane().setBackground(Color.CYAN);
        jf.setVisible(true);
        jf.setSize(700, 700);
        jf.setLayout(null);
        jf.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jf.validate();
        try {
            ss = new ServerSocket(5000);
            s = ss.accept();
            ss3 = new ServerSocket(3110);
            readsocket = ss3.accept();
            ss2 = new ServerSocket(888);
            socket = ss2.accept();
            din = new DataInputStream(s.getInputStream());
            dout = new DataOutputStream(s.getOutputStream());
            String line = "";
            while (line.equals("")) {
                try {
                    ipaddress = din.readUTF();
                    line = ipaddress;
                    reqtip.setText(ipaddress);
                } catch (Exception e) {
                }
            }
            din.close();
            s.close();
            ss.close();
            ois = new ObjectInputStream(readsocket.getInputStream());
            clientPublicKey = (PublicKey) ois.readObject();
            sign2 = (byte[]) ois.readObject();
            System.out.println(clientPublicKey);
            if (Verify_Digital_Signature(ipaddress.getBytes(), sign2, clientPublicKey) == true) {
                JOptionPane.showMessageDialog(jf,
                        "Verified IP Address" + "\n" + "Request from: "
                                + (readsocket.getInetAddress().toString().substring(1)));
            } else {
                JOptionPane.showMessageDialog(jf, "SUSPICIOUS");
            }

            ois.close();
            readsocket.close();
        } catch (Exception e) {
        }
    }

    public static double createsignature(int msg, int a, int n) {
        signature = Math.pow(msg, a) % n;
        return signature;
    }

    public static int gcd(int e, int z) {
        if (e == 0)
            return z;
        else
            return gcd(z % e, e);
    }

    public int geta(int phi) {
        int f = 0;
        for (int i = 2; i < phi; i++) {

            // e is for public key exponent
            if (gcd(i, phi) == 1) {
                f = i;
                break;
            }
        }
        return f;
    }

    public int getb(int a, int phi) {
        int flag = 0;
        int a_inv = 0;
        for (int j = 1; j < phi; j++) {
            flag = (a * j) % phi;
            if (gcd(flag, phi) == 1) {
                a_inv = flag;
                break;
            }
        }
        return a_inv;
    }

    public void actionPerformed(ActionEvent ae) {
        if (ae.getSource() == encryp) {
            String t = macreq.getText();
            encryptedval = encrypt(t);
            emac.setText(encryptedval);
        }
        if (ae.getSource() == getmac) {
            try {
                String op;
                InetAddress address = InetAddress.getLocalHost();
                NetworkInterface ni = NetworkInterface.getByInetAddress(address);
                if (ni != null) {
                    byte[] mac = ni.getHardwareAddress();
                    if (mac != null) {
                        String st = " ";
                        for (int i = 0; i < mac.length; i++) {
                            st += String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : "");
                        }
                        macreq.setText(st);
                    } else {
                        op = "Address doesn't exist or is not accessible";
                        macreq.setText(op);
                    }
                } else {
                    op = "Network Interface for the specified address is not found";
                    macreq.setText(op);
                }
            } catch (UnknownHostException | SocketException e) {
            }
        }
        if (ae.getSource() == send) {

            String encrypmac = emac.getText();
            a = geta(phi);
            b = getb(a, phi);
            char[] st = encrypmac.toCharArray();
            int x = st[0];
            int y = st[st.length - 1];
            int msg = x + y;
            double sig = createsignature(msg, a, phi);
            int sign = ((int) sig);
            String encrypwithsig = encrypmac + "," + secretkey + "," + saltvalue + "," + Integer.toString(sign) + ","
                    + Integer.toString(b) + ","
                    + Integer.toString(phi);
            try {

                dout = new DataOutputStream(socket.getOutputStream());
                dout.writeUTF(encrypwithsig);
                dout.flush();
                dout.close();

            } catch (Exception e) {
            }

        }
    }

    public static String encrypt(String str) {
        try {
            secretkey = JOptionPane.showInputDialog(jf, "Enter the secretkey");
            saltvalue = JOptionPane.showInputDialog(jf, "Enter the salt value:");
            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec keyspec = new PBEKeySpec(secretkey.toCharArray(), saltvalue.getBytes(), 65536, 256);
            SecretKey skey = skf.generateSecret(keyspec);
            SecretKeySpec skeyspec = new SecretKeySpec(skey.getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeyspec, ivspec);
            return Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Exception Occured " + e);
        }
        return null;
    }

    public static boolean Verify_Digital_Signature(
            byte[] input,
            byte[] signatureToVerify,
            PublicKey key)
            throws Exception {
        Signature signat = Signature.getInstance(
                SIGNING_ALGORITHM);
        signat.initVerify(key);
        signat.update(input);
        return signat
                .verify(signatureToVerify);
    }

    public static void main(String[] args) {
        TestServer sg = new TestServer();
    }
}
