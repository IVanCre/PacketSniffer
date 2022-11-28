
using WinDivertSharp;
using System.Drawing;


namespace PacketSniffer
{
    public class AllStructs
    {
        public struct ParsedPacketData
        {
            public string typeHeader;
            public TcpHeader headerStruct;
            public string direction;

            public string sourceAdress;
            public int sourcePort;

            public string destAdress;
            public int destPort;

            public int lenOfAllPacket;
            public int dataLenBytes;
            public byte icmpByteCode;

        }
        public struct ColorIndication
        {
            public static Color Skipped = Color.Red;
            public static Color CrashHexSum = Color.Orange;
            public static Color Wait = Color.Yellow;
            public static Color Copy = Color.Blue;
            public static Color Sniff = Color.Green;
        }

        public struct PacketNode
        {
            public WinDivertBuffer packet;
            public uint readLenPacketBits;
            public WinDivertAddress addr;
            public Color colorOfRow;
            public MainForm mainFormRef;
            public int packetNum;

            public void Create( WinDivertBuffer _packet, uint _readLenPacketBits, WinDivertAddress _addr,MainForm refF,Color color, int pacNumber)
            {
                packet = _packet;
                readLenPacketBits = _readLenPacketBits;
                addr = _addr;
                mainFormRef = refF;
                colorOfRow = color;
                packetNum = pacNumber;
            }
        }

    }
}
