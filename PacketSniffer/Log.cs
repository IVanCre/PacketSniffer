using System;
using System.IO;
using System.Reflection;


namespace PacketSniffer
{
    public class Log
    {
        private static readonly object sync = new object();
        public static string realPath = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + "Files\\Logs";

        public static void SaveLog(string text)
        {
            try
            {
                lock (sync)
                {
                    string dateNow = DateTime.Now.ToShortDateString();
                    string time = DateTime.Now.ToString();
                    File.AppendAllText($@"{realPath}\{dateNow}.txt", "\n"+time + " " + text + " \n");
                }
            }
            catch(Exception e)
            { }
        }
    }
}
