# E-mail server/client architecture emulator
This is the Java baseline application for the exam. 

The application is insecure, the student must secure it against the studied attacks.

## Instructions for using the application
### Required tools
- [Java JDK 11](https://www.oracle.com/java/technologies/downloads/#java11) or higher;
- [Eclipse IDE](https://www.eclipse.org/downloads/);
- MySQL Server and MySQL Workbench, follow this [video](https://www.youtube.com/watch?v=YSOY_NyOg40) (during installation remember to set password to "root").

### Eclipse IDE setup
1. Open Eclipse
2. Go to Help -> Install new software... -> Work with: "Latest Eclipse Simultaneous Release - https://download.eclipse.org/releases/latest"
   * In the tab below, expand the "Web, XML, Java EE and OSGi Enterprise Development" checkbox
   * Check only the following elements:
     - Eclipse Java EE Developer Tools
     - Eclipse Java Web Developer Tools
     - Eclipse Java Web Developer Tools - JavaScript Support
     - Eclipse Web Developer Tools
     - Eclipse Web JavaScript Developer Tools
     - JST Server Adapters
     - JST Server Adapters Extension (Apache Tomcat)
   * Click Next two times, then accept the license and click Finish
3. Restart Eclipse

### Tomcat WebServer setup
1. Open Eclipse
2. Go to Window -> Preferences -> Server -> Runtime Environments -> Add... -> Apache -> Apache Tomcat v10.0 -> Thick 'Create new a local server' -> Next
3. Click 'Download and install...', that should install the latest stable version (currently 10.0.13) -> Choose your favourite folder for Tomcat installation
4. Since now you can see your installed web servers in the Eclipse 'Server' tab, if it is not displayed by default, you can enable it by going to Window -> Show view -> Server

### MySQL setup
1. Open MySQL Workbench
2. Double click on the local instance of MySQL
3. Create a new SQL tab for executing queries, paste the following query and execute it

```sql
CREATE DATABASE mail_db;

CREATE TABLE mail_db.user (
	name varchar(50)  NOT NULL,
	surname varchar(50) NOT NULL,
	email varchar(50) NOT NULL,
	password varchar(50) NOT NULL,
	CONSTRAINT user_PK PRIMARY KEY (email)
);

CREATE TABLE mail_db.mail (
	sender varchar(50) NOT NULL,
	receiver varchar(50) NOT NULL,
	subject varchar(100) NULL,
	body text NOT NULL,
	time datetime NOT NULL,
	CONSTRAINT mail_FK FOREIGN KEY (sender) REFERENCES user(email) ON DELETE CASCADE,
	CONSTRAINT mail_FK_1 FOREIGN KEY (receiver) REFERENCES user(email) ON DELETE CASCADE
);
```

### Project setup
- If you want to create a brand new project
  1. Go to File -> New -> Project... -> Web -> Dynamic Web Application
  2. Name your project as you want (e.g. ExamProject) -> click Next two times -> Thick 'Generate web.xml deployment descriptor' -> click Finish
  3. Right click on the newly created project -> Build path -> Configure build path...
  4. Go to Libraries -> Click on classpath -> Add External Jars... -> Add the file "servlet-api.jar" from lib directory inside the Apache Tomcat folder

- If you want to import this project from GitHub
  1. Import it with Eclipse
  3. Right click on the project -> Build path -> Configure build path...
  4. Go to Libraries -> Click on classpath -> Add External Jars... -> Add the file "servlet-api.jar" from lib directory inside the Apache Tomcat folder

**You're ready now to build your Web Application using Java and Tomcat!**

By using Eclipse you can...
1. Create Servlets: right click on project -> New -> Servlet (note that Eclipse auto-generated servlets import the old 'javax' package still, replace it with 'jakarta' to work properly)
2. Create HTTP/JSP/CSS/JavaScript files: right click on project -> New -> HTTP/JSP/CSS/JavaScript file
3. Run your web application: right click on project -> Run As -> Run on Server -> Select the Apache Tomcat server -> Run -> Go to your browser on URL "http://localhost:8080/ExamProject/"
