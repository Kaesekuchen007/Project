package util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class Util {
	public static final String USER = "root";
	public static final String PWD = "root";
	public static final String DRIVER_CLASS = "com.mysql.cj.jdbc.Driver";
	public static final String DB_NAME = "mailClient_db";
	public static final String DB_URL = "jdbc:mysql://localhost:3306/" + DB_NAME;
		
	public static final Connection initDbConnection() {
		try {
			Class.forName(DRIVER_CLASS);
			
		    Properties connectionProps = new Properties();
		    connectionProps.put("user", USER);
		    connectionProps.put("password", PWD);
	
	        return DriverManager.getConnection(DB_URL, connectionProps);
		    
		    //System.out.println("User \"" + USER + "\" connected to database.");
    	
    	} catch (ClassNotFoundException | SQLException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static byte[]decryptWithDerivedKey(String encryptedData, byte[] derivedKey) {
	    try {
	        // Decode the encrypted data
	        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

	        // Use the derived key
	        SecretKeySpec secretKey = new SecretKeySpec(derivedKey, "AES");

	        // Decrypt
	        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey);
	        
	        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

	        // Convert to string and return
	        return decryptedBytes;
	        
	    } catch (Exception e) {
	        e.printStackTrace();
	        return null;
	    }
	}

}





