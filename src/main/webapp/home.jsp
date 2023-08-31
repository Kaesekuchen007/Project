<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.apache.commons.text.StringEscapeUtils" %>

<!DOCTYPE html>
<html>
<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1">
	<link rel="stylesheet" href="style.css" type="text/css" />
    <title>Home Page</title>
</head>
<body>
   <nav class="navbar">
    <div class="logo-container">
        <img src="images/email_icon.jpg" alt="Email Icon" class="email-icon" style="width: 50px; height: 50px;">
    </div>
    <div class="info-logout-container">
        <p class="user-email"><%= StringEscapeUtils.escapeHtml4((String)session.getAttribute("email")) %></p>
        <a href="login.html" class="logout-btn">Logout</a>
    </div>
</nav>
    <main class="main-content">
        <div class="left-column">
            <!-- Navigation buttons for SendMailServlet -->
            <form class="btn-group" action="SendMailServlet" method="post">
                <input type="hidden" name="email" value="<%= session.getAttribute("email") %>">
                <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                <input type="text" name="receiver" placeholder="Receiver">
                <input type="text" name="subject" placeholder="Subject">
                <textarea name="body" placeholder="Body"></textarea>
                <input type="checkbox" id="digitalSign" name="digitalSign" value= "true">
                <label for="digitalSign">Digitally Sign Email</label><br>
                <button type="submit" name="newMail" class="btn">Send Mail</button>
            </form>
        </div>
        <div class="right-column">
            <!-- Navigation buttons for ReceiveMailServlet -->
            <form class="btn-group" action="ReceiveMailServlet" method="post">
                <input type="hidden" name="email" value="<%= session.getAttribute("email") %>">
                <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                <button type="submit" name="inbox" class="btn">Inbox</button>
            </form>
            <!-- Navigation buttons for NavigationServlet -->
            <form class="btn-group" action="NavigationServlet" method="post">
                <input type="hidden" name="email" value="<%= session.getAttribute("email") %>">
                <input type="hidden" name="csrfToken" value="<%= session.getAttribute("csrfToken") %>">
                <button type="submit" name="sent" class="btn">Sent</button>
            </form>
            
            <div class="content-area">
                <!-- Inbox Emails Display -->
                <div class="inbox-emails">
                    <% 
                        List<Map<String, Object>> inboxEmails = (List<Map<String, Object>>) request.getAttribute("inboxEmails"); 
                        if(inboxEmails != null && !inboxEmails.isEmpty()) {
                    %>
                    <table>
                        <thead>
                            <tr>
                                <th>Sender</th>
                                <th>Subject</th>
                                <th>Timestamp</th>
                                <th>Is Verified</th>
                                <th>Content</th>
                            </tr>
                        </thead>
                        <tbody>
                            <% 
                                for(Map<String, Object> email : inboxEmails) { 
                            %>
                                <tr>
                                    <td><%= email.get("sender") %></td>
                                    <td><%= email.get("subject") %></td>
                                    <td><%= email.get("timestamp") %></td>
                                    <td><%= email.get("isValid") %></td>
                                    <td><%= email.get("body") %></td>
                                </tr>
                            <% 
                                } 
                            %>
                        </tbody>
                    </table>
                    <% 
                        } else { 
                    %>
                    <% 
                        } 
                    %>
                    <div class="dynamic-content">
                        <%= request.getAttribute("content") %>
                    </div>
                </div>
            </div>
        </div>
    </main>
</body>
</html>
