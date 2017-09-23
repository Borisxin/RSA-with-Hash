import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import java.awt.Label;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.Base64;
import java.awt.event.ActionEvent;
import java.awt.Color;
import java.awt.Font;

public class ClientRSA extends JFrame {

	private JPanel contentPane;
	private JTextField IPADDRESS;
	private JTextField PORT;
	private JTextField CIPHER;
	private int port;
	private String IP;
	private String Content;
	private Socket sock;
	private BufferedReader  reader;           
	private PrintStream  writer;
	private JTextArea RESULT;
	private PublicKey publicKey;
	private PrivateKey privateKey;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ClientRSA frame = new ClientRSA();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 */
	public ClientRSA() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 663, 612);
		contentPane = new JPanel();
		contentPane.setBackground(Color.PINK);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		Label label = new Label("IP\uFF1A");
		label.setFont(new Font("Blackadder ITC", Font.PLAIN, 19));
		label.setBounds(27, 33, 48, 25);
		contentPane.add(label);
		
		Label label_1 = new Label("Port\uFF1A");
		label_1.setFont(new Font("Blackadder ITC", Font.PLAIN, 18));
		label_1.setBounds(27, 93, 48, 25);
		contentPane.add(label_1);
		
		IPADDRESS = new JTextField();
		IPADDRESS.setBounds(95, 33, 184, 25);
		contentPane.add(IPADDRESS);
		IPADDRESS.setColumns(10);
		
		PORT = new JTextField();
		PORT.setBounds(95, 93, 184, 25);
		contentPane.add(PORT);
		PORT.setColumns(10);
		
		JButton Connect = new JButton("Connect");
		Connect.setFont(new Font("Blackadder ITC", Font.PLAIN, 18));
		Connect.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				IP=IPADDRESS.getText();
				port=Integer.parseInt(PORT.getText());
				EstablishConnection();
				Thread readerThread = new Thread(new IncomingReader());  
				readerThread.start();
			}
		});
		
		Connect.setBounds(27, 145, 99, 27);
		contentPane.add(Connect);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(36, 275, 513, 258);
		contentPane.add(scrollPane);
		
		RESULT = new JTextArea();
		scrollPane.setViewportView(RESULT);
		
		Label label_2 = new Label("Cipher\uFF1A");
		label_2.setFont(new Font("Blackadder ITC", Font.PLAIN, 18));
		label_2.setBounds(27, 196, 65, 25);
		contentPane.add(label_2);
		
		CIPHER = new JTextField();
		CIPHER.setColumns(10);
		CIPHER.setBounds(95, 196, 184, 25);
		contentPane.add(CIPHER);
		
		JButton btnNewButton = new JButton("Submit");
		btnNewButton.setFont(new Font("Blackadder ITC", Font.PLAIN, 18));
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				final Base64.Encoder encoder = Base64.getEncoder();
				Content=CIPHER.getText();
				if(!Content.isEmpty()){
					try {
						byte[] cipher=Content.getBytes("UTF-8");
						RsaKeyPair();
						cipher=encryptHash(cipher);
						RESULT.append("---正在加密內容---\n");
						RESULT.append("內容為："+Content+"\n");
						RESULT.append("Hash過後的資料為："+encoder.encodeToString(cipher)+"\n");
						cipher=encryptRSA(cipher,privateKey);
						RESULT.append("RSA加密後的資料為："+encoder.encodeToString(cipher)+"\n");
						String key = null;
						try {
							key=getKeyString(publicKey);
						} catch (Exception e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						writer.println(key);
						writer.println(encoder.encodeToString(cipher));
						writer.println(Content);
						RESULT.append("---已傳送內容至Server端---\n\n");
					} catch (UnsupportedEncodingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
				else{
				   RESULT.append("請輸入要加密的資料喔!\n");
				}
			}
		});
		btnNewButton.setBounds(27, 235, 99, 27);
		contentPane.add(btnNewButton);
	}
	private void EstablishConnection(){
		  try{
		   sock = new Socket(IP,port);      
		   InputStreamReader streamReader =  new InputStreamReader(sock.getInputStream());  
		   reader = new BufferedReader(streamReader);    
		   
		   writer = new PrintStream(sock.getOutputStream());
		  
		   RESULT.append("網路建立-連線成功\n");    
		   
		  }catch(IOException ex ){
			  RESULT.append("建立連線失敗\n");
		  }
	}
	public void RsaKeyPair() throws NoSuchAlgorithmException{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		random.setSeed("Helloworld".getBytes());
		keygen.initialize(1024, random); // 生成 1024-bit 金鑰
		KeyPair rsaKeyPair = keygen.generateKeyPair();
		publicKey = rsaKeyPair.getPublic();
		privateKey = rsaKeyPair.getPrivate();
		}
	private static byte[] encryptRSA(byte[] data,PrivateKey privatekey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
			Cipher cipher;
			try {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, privatekey);
				return cipher.doFinal(data);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;
		
	}
	private static byte[] decryptRSA(byte[] data,PublicKey publickey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, publickey);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	
}
    private static byte[] encryptHash(byte[] data) throws NoSuchAlgorithmException{
    	MessageDigest sha=MessageDigest.getInstance("SHA");
    	sha.update(data);
    	return sha.digest();
    }
    public static String getKeyString(Key key) throws Exception {
    	final Base64.Encoder encoder = Base64.getEncoder();
        byte[] keyBytes = key.getEncoded();
        String s = encoder.encodeToString(keyBytes);
        return s;
  }
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        final Base64.Decoder decoder = Base64.getDecoder();
        keyBytes = decoder.decode(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
  }
    public class IncomingReader implements Runnable{
		  public void run(){
		   String message;
		  
		   try{
		    while ((message =reader.readLine())!=null){
		    	RESULT.append("---Server回傳的資料---\n");
		    	RESULT.append(message+"\n");
		    	RESULT.append("---Server回傳的資料---\n\n");
		    }
		   }catch(Exception ex ){ex.printStackTrace();}
		  }
		 } 
}
