using WinDivertSharp;
using System;

namespace PacketSniffer
{
    class UdpPacketFuncs
    {
        unsafe public static void ParsePacket(ref AllStructs.ParsedPacketData parsedPack, ref WinDivertParseResult pacResult, int verIP)
        {
            try
            {
                parsedPack.sourcePort = (int)swapUint((*pacResult.UdpHeader).SrcPort);
                parsedPack.destPort = (int)swapUint((*pacResult.UdpHeader).DstPort);

                switch (verIP)
                {
                    case 4:
                        {
                            parsedPack.typeHeader = "IPv4 UDP";
                            parsedPack.sourceAdress = $"{ (*pacResult.IPv4Header).SrcAddr}";
                            parsedPack.destAdress = $"{(*pacResult.IPv4Header).DstAddr}";
                            break;
                        }
                    case 6:
                        {
                            parsedPack.typeHeader = "IPv6 UDP";
                            parsedPack.sourceAdress = $"{ (*pacResult.IPv6Header).SrcAddr}";
                            parsedPack.destAdress = $"{(*pacResult.IPv6Header).DstAddr}";
                            break;
                        }
                }
            }
            catch (Exception e)
            {
                Log.SaveLog("fail parse UDP packet ={e}");
            }
        }

        private static uint swapUint(uint toSwap)// конвертит порядок байтов.  Типа из big-endian to little-endian  или наоборот, в зависимости в какой нотации текущее 
        {
            try
            {
                int tmp = 0;
                tmp = (int)(toSwap >> 8);
                tmp = (int)(tmp | ((toSwap & 0xff) << 8));
                return (uint)tmp;
            }
            catch (Exception e)
            {
                Log.SaveLog($"fail when swap Big_Little endian ={e}");
                return 0;
            }
        }

    }
}
