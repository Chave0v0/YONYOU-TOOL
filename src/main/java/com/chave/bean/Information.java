package com.chave.bean;

public class Information {
    public static String DNSLOG = null;
    public static String PROXY = null;
    public static String MOD = null;
    public static String TARGET = null;
    public static String VULN = null;
    public static String HELP = "Usage: java -jar YONYOU-TOOL.jar [Options]\n" +
            "  Options:\n" +
            "    -h, --help        Show this help\n" +
            "    -t, --target      Set target url  (e.g.: http://0.0.0.0:443)\n" +
            "    -m, --module      Set module  (support: poc exp)\n" +
            "    -v, --vuln        Set vulnerability  (e.g.: ActionHandlerServlet)\n" +
            "    -p, --proxy       Set http proxy  (e.g.: http://127.0.0.1:8080)\n" +
            "    -d, --dnslog      Set dnslog platform\n" +
            "  Vuln Support:\n" +
            "    1. ActionHandlerServlet\n" +
            "  Tips:\n" +
            "    1. You must specify the target, vuln, mod parameters.\n" +
            "    2. When mod is set to poc, the dnslog parameter must be specified.";

}
