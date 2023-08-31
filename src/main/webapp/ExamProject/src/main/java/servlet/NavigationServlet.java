package servlet;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import util.Util;

@WebServlet("/NavigationServlet")
public class NavigationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static Connection conn;

    public NavigationServlet() {
        super();
    }

    public void init() {
        conn = Util.initDbConnection();  // Initialize the database connection
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) 
            throws ServletException, IOException {
        response.setContentType("text/html");

        HttpSession session = request.getSession();
        String sessionCSRFToken = (String) session.getAttribute("csrfToken");
        String requestCSRFToken = request.getParameter("csrfToken");

        if (sessionCSRFToken == null || !sessionCSRFToken.equals(requestCSRFToken)) {
            response.getWriter().write("Invalid CSRF Token");
            return;
        }

        String email = htmlEscape(request.getParameter("email"));
        String pwd = htmlEscape(request.getParameter("password"));

        try {
            if (request.getParameter("newMail") != null) {
                request.setAttribute("content", getHtmlForNewMail(email, pwd));
            } else if (request.getParameter("inbox") != null) {
                request.setAttribute("content", getHtmlForInbox(email, pwd, htmlEscape(request.getParameter("search"))));
            } else if (request.getParameter("sent") != null) {
                request.setAttribute("content", getHtmlForSent(email, pwd, htmlEscape(request.getParameter("search"))));
            }

            request.setAttribute("email", email);
            request.getRequestDispatcher("home.jsp").forward(request, response);
        } catch (SQLException e) {
            e.printStackTrace();
            response.getWriter().write("Database error!");
        }
    }

    // Method to perform HTML escaping to avoid XSS
    public String htmlEscape(String input) {
        if(input == null) return null;
        return input.replaceAll("&", "&amp;")
                    .replaceAll("<", "&lt;")
                    .replaceAll(">", "&gt;")
                    .replaceAll("\"", "&quot;")
                    .replaceAll("'", "&#39;");
    }

    private String getHtmlForNewMail(String email, String pwd) {
        return "<form id=\"submitForm\" class=\"form-resize\" action=\"SendMailServlet\" method=\"post\">"
                + "<input type=\"hidden\" name=\"email\" value=\"" + htmlEscape(email) + "\">"
                + "<input type=\"hidden\" name=\"password\" value=\"" + htmlEscape(pwd) + "\">"
                + "<input class=\"single-row-input\" type=\"email\" name=\"receiver\" placeholder=\"Receiver\" required>"
                + "<input class=\"single-row-input\" type=\"text\" name=\"subject\" placeholder=\"Subject\" required>"
                + "<textarea class=\"textarea-input\" name=\"body\" placeholder=\"Body\" wrap=\"hard\" required></textarea>"
                + "<input type=\"submit\" name=\"sent\" value=\"Send\">"
                + "</form>";
    }

    private String getHtmlForInbox(String receiver, String password, String sender) throws SQLException {
        String query = sender == null ? 
            "SELECT * FROM mail WHERE receiver = ? ORDER BY time DESC" :
            "SELECT * FROM mail WHERE receiver = ? AND sender = ? ORDER BY time DESC";

        StringBuilder output = new StringBuilder();
        output.append("<div>\r\n")
            .append("<form action=\"NavigationServlet\" method=\"post\">\r\n")
            .append("    <input type=\"hidden\" name=\"email\" value=\"" + htmlEscape(receiver) + "\">\r\n")
            .append("    <input type=\"hidden\" name=\"password\" value=\"" + htmlEscape(password) + "\">\r\n")
            .append("    <input type=\"text\" placeholder=\"Search for sender\" name=\"search\" required>\r\n")
            .append("    <input type=\"submit\" name=\"inbox\" value=\"Search\">\r\n")
            .append("</form>\r\n");

        try (PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, receiver);
            if (sender != null) ps.setString(2, sender);
            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">")
                    .append("FROM: " + htmlEscape(rs.getString("sender")) + " AT: " + htmlEscape(rs.getString("time")))
                    .append("</span>")
                    .append("<br><b>" + htmlEscape(rs.getString("subject")) + "</b>\r\n")
                    .append("<br>" + htmlEscape(rs.getString("body")) + "</div>\r\n")
                    .append("<hr>");
            }
        }

        return output.toString();
    }

    private String getHtmlForSent(String sender, String password, String receiver) throws SQLException {
        String query = receiver == null ? 
            "SELECT * FROM mail WHERE sender = ? ORDER BY time DESC" :
            "SELECT * FROM mail WHERE sender = ? AND receiver = ? ORDER BY time DESC";

        StringBuilder output = new StringBuilder();
        output.append("<div>\r\n")
            .append("<form action=\"NavigationServlet\" method=\"post\">\r\n")
            .append("    <input type=\"hidden\" name=\"email\" value=\"" + htmlEscape(sender) + "\">\r\n")
            .append("    <input type=\"hidden\" name=\"password\" value=\"" + htmlEscape(password) + "\">\r\n")
            .append("    <input type=\"text\" placeholder=\"Search for receiver\" name=\"search\" required>\r\n")
            .append("    <input type=\"submit\" name=\"sent\" value=\"Search\">\r\n")
            .append("</form>\r\n");

        try (PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setString(1, sender);
            if (receiver != null) ps.setString(2, receiver);
            ResultSet rs = ps.executeQuery();

            while (rs.next()) {
                output.append("<div style=\"white-space: pre-wrap;\"><span style=\"color:grey;\">")
                    .append("TO: " + htmlEscape(rs.getString("receiver")) + " AT: " + htmlEscape(rs.getString("time")))
                    .append("</span>")
                    .append("<br><b>" + htmlEscape(rs.getString("subject")) + "</b>\r\n")
                    .append("<br>" + htmlEscape(rs.getString("body")) + "</div>\r\n")
                    .append("<hr>");
            }
        }

        return output.toString();
    }
}
