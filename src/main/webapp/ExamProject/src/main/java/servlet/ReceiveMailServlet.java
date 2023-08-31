package servlet;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import util.Util;

import java.io.IOException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.util.*;

@WebServlet("/ReceiveMailServlet")
public class ReceiveMailServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Connection conn;

    public ReceiveMailServlet() {
        super();
    }

    public void init() {
        conn = Util.initDbConnection();
    }

    private boolean validateSignature(String publicKeyPem, String digitalSignature, String emailBody) {
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
            byte[] signatureBytes = Base64.getDecoder().decode(digitalSignature);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            PublicKey publicKey = java.security.KeyFactory.getInstance("RSA").generatePublic(keySpec);

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(emailBody.getBytes("UTF-8"));

            return signature.verify(signatureBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    	String userEmail = request.getParameter("email");

    	System.out.println(userEmail);
    	List<Map<String, Object>> emails = new ArrayList<>();
        String query = "SELECT m.*, u.publicKey FROM mail m LEFT JOIN user u ON m.sender = u.email WHERE receiver = ?";
        		
        try (PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, userEmail);
            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                Map<String, Object> emailDetails = new HashMap<>();
                emailDetails.put("sender", rs.getString("sender"));
                emailDetails.put("subject", rs.getString("subject"));
                emailDetails.put("body", rs.getString("body"));
                emailDetails.put("timestamp", rs.getString("time"));
                
                String publicKeyPem = rs.getString("publicKey");
                String digitalSignature = rs.getString("digital_signature");

                boolean isSigned = (digitalSignature != null && publicKeyPem != null);
                emailDetails.put("isSigned", isSigned);

                boolean isValid = false;
                if (isSigned) {
                    isValid = validateSignature(publicKeyPem, digitalSignature, rs.getString("body"));
                }
                emailDetails.put("isValid", isValid);
                
                emails.add(emailDetails);
            }
            request.setAttribute("inboxEmails", emails);
            System.out.println("email" + request.getParameter("email"));
            request.getRequestDispatcher("/home.jsp").forward(request, response);            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
