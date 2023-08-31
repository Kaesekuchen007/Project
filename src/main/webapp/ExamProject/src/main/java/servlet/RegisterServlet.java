package servlet;

import util.Util;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.regex.Pattern;

@WebServlet("/RegisterServlet")
public class RegisterServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Connection conn;

    public RegisterServlet() {
        super();
    }

    public void init() throws ServletException {
        conn = Util.initDbConnection();
    }

    private static String generateCsrfToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[16];
        secureRandom.nextBytes(tokenBytes);
        StringBuilder sb = new StringBuilder();
        for (byte b : tokenBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean isStrongPassword(String password) {
        String regex = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$";
        return Pattern.matches(regex, password);
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.generateKeyPair();
    }

    private String encryptPrivateKey(String privateKey, byte[] derivedKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(derivedKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedPrivateKeyBytes = cipher.doFinal(Base64.getDecoder().decode(privateKey));
        return Base64.getEncoder().encodeToString(encryptedPrivateKeyBytes);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String name = request.getParameter("name");
        String surname = request.getParameter("surname");
        String email = request.getParameter("email");
        String pwd = request.getParameter("password");

        if (!isStrongPassword(pwd)) {
            String error = "Password must be strong.";
            response.sendRedirect("register.html?error=" + java.net.URLEncoder.encode(error, "UTF-8"));
            return;
        }

        try {
            String hashedPassword = hashPassword(pwd);

            PreparedStatement checkEmailStmt = conn.prepareStatement("SELECT * FROM user WHERE email = ?");
            checkEmailStmt.setString(1, email);
            ResultSet sqlRes = checkEmailStmt.executeQuery();

            if (sqlRes.next()) {
                String error = "Email already registered!";
                response.sendRedirect("register.html?error=" + java.net.URLEncoder.encode(error, "UTF-8"));
                return;
            }

            KeyPair keyPair = generateKeyPair();
            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            char[] passwordChars = pwd.toCharArray();
            byte[] salt = new byte[16];
            PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 65536, 128);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] derivedKey = skf.generateSecret(spec).getEncoded();

            String encryptedPrivateKey = encryptPrivateKey(privateKey, derivedKey);

            PreparedStatement insertUserStmt = conn.prepareStatement("INSERT INTO user (name, surname, email, password, publicKey, privateKey) VALUES (?, ?, ?, ?, ?, ?)");
            insertUserStmt.setString(1, name);
            insertUserStmt.setString(2, surname);
            insertUserStmt.setString(3, email);
            insertUserStmt.setString(4, hashedPassword);
            insertUserStmt.setString(5, publicKey);
            insertUserStmt.setString(6, encryptedPrivateKey);
            insertUserStmt.executeUpdate();

            HttpSession session = request.getSession();
            String csrfToken = generateCsrfToken();
            session.setAttribute("csrfToken", csrfToken);
            session.setAttribute("email", email);
            response.sendRedirect("home.jsp");

            request.setAttribute("email", email);

        } catch (SQLException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            response.sendRedirect("register.html?error=Registration%20Failed");
        } catch (Exception e) {
            e.printStackTrace();
            response.sendRedirect("register.html?error=Encryption%20Failed");
        }
    }
}
