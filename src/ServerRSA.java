import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.util.Arrays;
import java.awt.Label;
import javax.swing.JTextField;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import java.util.Vector;
import java.awt.event.ActionEvent;
import java.awt.Color;
import java.awt.Font;
public class ServerRSA extends JFrame {

	private JPanel contentPane;
	private JTextField textField;
	private int portnum;
    private ServerSocket serverSock;
    private Vector<PrintStream> output;
    private PublicKey publicKey;
    public JTextArea result;
    
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ServerRSA frame = new ServerRSA();
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
	public ServerRSA() {
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 562, 456);
		contentPane = new JPanel();
		contentPane.setBackground(Color.PINK);
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		Label label = new Label("Port\uFF1A");
		label.setFont(new Font("Blackadder ITC", Font.PLAIN, 18));
		label.setBounds(10, 31, 49, 25);
		contentPane.add(label);
		
		textField = new JTextField();
		textField.setBounds(68, 31, 116, 25);
		contentPane.add(textField);
		textField.setColumns(10);
		
		JButton btnOpen = new JButton("Open");
		btnOpen.setFont(new Font("Blackadder ITC", Font.PLAIN, 15));
		btnOpen.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				output = new Vector<PrintStream>();
			    portnum = Integer.parseInt(textField.getText());
				Thread s=new Thread(new Accept(portnum));
				s.start();
				result.append("port 已被連線");
			}
		});
		btnOpen.setBounds(14, 83, 99, 27);
		contentPane.add(btnOpen);
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setBounds(24, 123, 473, 273);
		contentPane.add(scrollPane);
		
		result = new JTextArea();
		scrollPane.setViewportView(result);
	}
	private static byte[] encryptHash(byte[] data) throws NoSuchAlgorithmException{
    	MessageDigest sha=MessageDigest.getInstance("SHA");
    	sha.update(data);
    	return sha.digest();
    }
	public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        final Base64.Decoder decoder = Base64.getDecoder();
        keyBytes = decoder.decode(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
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
	public class Accept implements Runnable{
		int portnum;
		public Accept(int portnum){
			this.portnum=portnum;
		}
		@Override
		public void run() {
			 try{
				   
				   serverSock = new ServerSocket(portnum); 
				   while(true){
				    Socket cSocket = serverSock.accept();    
				    PrintStream writer =  new PrintStream(cSocket.getOutputStream());  
				    output.add(writer);         
				    Thread t = new Thread(new Process(cSocket)); 
				    t.start();           
				    result.append("有人連線!!!\n");
			             
				  } 
				  }catch(Exception ex){System.out.println("連接失敗");}
			
		}
		
	}
	public class Process implements Runnable{   
		  BufferedReader reader;  
		  Socket sock;            
		  public Process(Socket cSocket)
		  {
		   try{
		    sock = cSocket;
		    InputStreamReader isReader =  new InputStreamReader(sock.getInputStream()); 
		    reader = new BufferedReader(isReader);
		   }catch(Exception ex){
		    System.out.println("連接失敗Process");
		   } 
		  }
		  public void run(){
		   String data;
		   String content;
		   String key;
		   try{
		    while ((key = reader.readLine())!=null && (data = reader.readLine()) !=null && (content = reader.readLine()) !=null){  
		    	publicKey=getPublicKey(key);
		    	result.append("----接受到一份資料----\n");
		    	result.append("內容為："+content+"\n");
		    	
		    	final Base64.Decoder decoder = Base64.getDecoder();
		    	final Base64.Encoder encoder = Base64.getEncoder();
		    	byte[] encryptdata=decoder.decode(data);
		    	byte[] Content=content.getBytes();
		    	byte[] Result=ServerRSA.decryptRSA(encryptdata, publicKey);
		    	
		    	Content=encryptHash(Content);
		    	String a,b;
		    	a=encoder.encodeToString(Content);
		    	b=encoder.encodeToString(Result);
		    	result.append("解密後的資料為："+b+"\n");
		    	result.append("以收到的內容進行Hash後的結果為："+a+"\n");
		    	if(a.equals(b)){
		    		result.append("相同，驗證為本人傳送!\n");
		    		tellApiece("相同");
		    	}
		    	else{
		    		result.append("不同，有人修改過!\n");
		    		tellApiece("不同");
		    	}
		    }
		   }catch(Exception ex){result.append("有一個連接離開\n");}
		  }
		  public void tellApiece(String message){
			   Iterator<PrintStream> it = output.iterator(); 
			   while(it.hasNext()){          
			    try{
			    PrintStream writer = (PrintStream) it.next();  
			    writer.println(message); 
			    writer.flush();           
			    }
			    catch(Exception ex){
			    	result.append("連接失敗Process\n");
			    }
			   }
			  }
		 }
}
