using WinDivertSharp;
using System;

namespace PacketSniffer
{
    class IcmpFuncs
    {
        unsafe public static void ParsePacket(ref AllStructs.ParsedPacketData parsedPack, ref WinDivertParseResult pacResult, int verIP)
        {
            try
            {
                switch (verIP)
                {
                    case 4:
                        {
                            parsedPack.typeHeader = "IPv4 ICMP";
                            parsedPack.icmpByteCode = (*pacResult.IcmpV4Header).Code;
                            break;
                        }
                    case 6:
                        {
                            parsedPack.typeHeader = "IPv6 ICMP";
                            parsedPack.icmpByteCode = (*pacResult.IcmpV6Header).Code;
                            break;
                        }
                }
            }
            catch(Exception e)
            {
                Log.SaveLog($"fail to parse ICMP packet ={e}");
            }

        }
    }
}
