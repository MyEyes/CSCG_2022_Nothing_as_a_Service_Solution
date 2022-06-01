using System;
using System.Runtime.Remoting.Channels; //To support and handle Channel and channel sinks
using System.Runtime.Remoting;
using System.Runtime.Remoting.Channels.Http; //For HTTP channel
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security;
using System.Security.Permissions;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Serialization.Formatters;
using System.Runtime.Remoting.Channels.Tcp;

namespace ServerApp
{
    //Server Class
    public class Server
    {
        //TypeFilterLevel to use.
        //When set to Low PoC causes DOS
        //When set to Full PoC causes RCE
        static TypeFilterLevel filterLevel = TypeFilterLevel.Full;

        //Set the service name
        static string ServiceName = "Service";

        public static void Main()
        {

            //Try block to catch anything, fails to capture DOS exception
            try
            {
                Hashtable hashtable = new Hashtable();
                ((IDictionary)hashtable)["port"] = 8001;
                ((IDictionary)hashtable)["rejectRemoteRequests"] = false; //Default value is false https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/bb397831(v=vs.100)
                BinaryServerFormatterSinkProvider binaryServerFormatterSinkProvider = new BinaryServerFormatterSinkProvider();
                binaryServerFormatterSinkProvider.TypeFilterLevel = filterLevel;
                var channel = new TcpChannel(hashtable, new BinaryClientFormatterSinkProvider(), binaryServerFormatterSinkProvider);

                //Register channel and service
                ChannelServices.RegisterChannel(channel, false);
                RemotingConfiguration.RegisterWellKnownServiceType(typeof(Service), ServiceName, WellKnownObjectMode.Singleton);

                //Wait for enter press
                Console.WriteLine("Server ON at port number:8001");
                Console.WriteLine("Please press enter to stop the server.");
                Console.ReadLine();
            }
            catch(Exception e)
            {
                Console.WriteLine("Could handle");
                Console.WriteLine(e);
                Console.ReadLine();
            }
        }
    }

    //Service class
    public class Service : MarshalByRefObject
    {
        public void WriteMessage(int num1, int num2)
        {
            Console.WriteLine(Math.Max(num1, num2));
        }
    }
}