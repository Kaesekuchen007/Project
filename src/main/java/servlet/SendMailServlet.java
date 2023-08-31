package servlet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import util.Util;

@WebServlet("/SendMailServlet")
public class SendMailServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Connection conn;

    public SendMailServlet() {
        super();
    }

    public void init() throws ServletException {
        conn = Util.initDbConnection();
    }

    private String getEncryptedPrivateKey(String email) {
        String encryptedPrivateKey = null;
        String query = "SELECT privateKey FROM user WHERE email = ?";
        
        try (PreparedStatement preparedStatement = conn.prepareStatement(query)) {
            preparedStatement.setString(1, email);
            
            ResultSet rs = preparedStatement.executeQuery();
            
            if (rs.next()) {
                encryptedPrivateKey = rs.getString("privateKey");
                if (encryptedPrivateKey == null) {
                    System.err.println("Encrypted private key is null in database for email: " + email);
                }
            } else {
                System.err.println("No user found with email: " + email);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("SQLException occurred while retrieving the private key.");
        }
        return encryptedPrivateKey;
    }
    
    private String createDigitalSignature(String data, byte[] privateKeyBytes) {
        // Check if privateKeyBytes is null
        if (privateKeyBytes == null) {
            System.err.println("privateKeyBytes is null. Cannot proceed with decoding.");
            return null; // Or throw a custom exception
        }

        // Check if data is null
        if (data == null) {
            System.err.println("Data for signing is null. Cannot proceed with signing.");
            return null; // Or throw a custom exception
        }

        try {
            // Since privateKeyBytes are already a byte array, no need for Base64 decoding
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);

            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey);
            signer.update(data.getBytes());

            byte[] signatureBytes = signer.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            // More robust handling here, e.g., log the exception to a file or send an alert
            return null;
        }
    }



    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        
        
        // Get parameters
        String sender = request.getParameter("email");
        String receiver = request.getParameter("receiver");
        String subject = request.getParameter("subject");
        String body = request.getParameter("body");
        String shouldSign = request.getParameter("digitalSign");
	
	if (shouldSign == null) {
        	shouldSign = "false";
        }
        
        // Additional null checks and logging
        if (sender == null || receiver == null || body == null){
            System.err.println("Some parameters are missing.");
            return;
        }

        // Get session and derived key
        HttpSession session = request.getSession();
        Object derivedKeyObject = session.getAttribute("derivedKey");

        byte[] derivedKeyBytes = null;
        System.out.println(derivedKeyObject);
if (derivedKeyObject instanceof byte[]) {
            derivedKeyBytes = (byte[]) derivedKeyObject;
        } else {
            System.err.println("Derived key is not a byte array");
            return;
        }

        // Date and time
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
        String timestamp = format.format(new Date());

        // Digital signature
        String digitalSignature = null;
        if ("true".equals(shouldSign) && derivedKeyBytes != null) {
            String encryptedPrivateKey = getEncryptedPrivateKey(sender);
            if (encryptedPrivateKey == null) {
                System.err.println("Failed to retrieve or decrypt the private key.");
                return;
            }

            // Assuming that Util.decryptWithDerivedKey can work with byte[]
            byte[] decryptedPrivateKey = Util.decryptWithDerivedKey(encryptedPrivateKey, derivedKeyBytes);
            digitalSignature = createDigitalSignature(body, decryptedPrivateKey);

            if (digitalSignature == null) {
                System.err.println("Failed to create a digital signature.");
                return;
            }
        }

        // Insert into the database
        String sqlQuery = "INSERT INTO mail (sender, receiver, subject, body, time, digital_signature) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement preparedStatement = conn.prepareStatement(sqlQuery)) {
            preparedStatement.setString(1, sender);
            preparedStatement.setString(2, receiver);
            preparedStatement.setString(3, subject);
            preparedStatement.setString(4, body);
            preparedStatement.setString(5, timestamp);
            preparedStatement.setString(6, digitalSignature);

            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println("Failed to insert email into the database.");
            return;
        }

        request.setAttribute("email", sender);
        request.getRequestDispatcher("home.jsp").forward(request, response);
    }

}
