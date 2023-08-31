package servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import util.Util;
import java.security.spec.InvalidKeySpecException;

@WebServlet("/LoginServlet")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Connection conn;

    public LoginServlet() {
        super();
    }

    // Generate CSRF Token
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

    public void init() throws ServletException {
        conn = Util.initDbConnection();
    }

    // Hash the password using SHA-256
    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes());
            byte[] bytes = md.digest();
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");

        String email = request.getParameter("email");
        String pwd = request.getParameter("password");
        String hashedPwd = hashPassword(pwd);

        String sql = "SELECT * FROM user WHERE email = ? AND password = ?";
        try (PreparedStatement preparedStatement = conn.prepareStatement(sql)) {
            preparedStatement.setString(1, email);
            preparedStatement.setString(2, hashedPwd);

            ResultSet sqlRes = preparedStatement.executeQuery();

            if (sqlRes.next()) {
                HttpSession session = request.getSession();

                // Generate CSRF token and store in session
                String csrfToken = generateCsrfToken();
                session.setAttribute("csrfToken", csrfToken);

                // Store the email in the session (this is the change)
                session.setAttribute("email", htmlEscape(sqlRes.getString(3)));
                try {
                    // Generate a derived key from the password
                    char[] passwordChars = pwd.toCharArray();
                    byte[] salt = new byte[16]; // Should be securely generated and stored
                    PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, 65536, 128);
                    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
                    byte[] derivedKey = skf.generateSecret(spec).getEncoded();

                    // Store the derived key in the session
                    session.setAttribute("derivedKey", derivedKey);

                } catch (InvalidKeySpecException e) {
                    e.printStackTrace();
                    // Handle the exception appropriately.
                }

                System.out.println("Login succeeded!");
                request.setAttribute("content", "");
                request.getRequestDispatcher("home.jsp").forward(request, response);
            } else {
                System.out.println("Login failed!");
                request.getRequestDispatcher("login.html").forward(request, response);
            }
        } catch (SQLException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            request.getRequestDispatcher("login.html").forward(request, response);
        }
    }

    // Utility function to escape HTML special characters, thus preventing XSS attacks
    private static String htmlEscape(String input) {
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
    }
}
