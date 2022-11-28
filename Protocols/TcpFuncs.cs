using WinDivertSharp;
using System;

namespace PacketSniffer
{
    public class TcpPacketFuncs
    {

        public static void CrashTcpHexSum(WinDivertBuffer packet, uint readLen)
        {
            //на основании структуры тсп-пакета:
            for (int i = 0; i < readLen; i++)
            {
                if (i > 127 && i < 145)//обнуляем все данные по контрольной сумме
                {
                    packet[i] = 0;
                    packet[i + 1] = 0;
                }
            }
        }
        public static  bool DetectTcp(string filter)
        {
            string lowWords = filter.ToLower();
            return lowWords.Contains("tcp");
        }


        unsafe public static void ParsePacket(ref AllStructs.ParsedPacketData parsedPack, ref WinDivertParseResult pacResult, int verIP)
        {
            try
            {
                parsedPack.headerStruct = *pacResult.TcpHeader;
                parsedPack.sourcePort = (int)swapUint((*pacResult.TcpHeader).SrcPort);
                parsedPack.destPort = (int)swapUint((*pacResult.TcpHeader).DstPort);

                switch (verIP)
                {
                    case 4:
                        {
                            parsedPack.typeHeader = "IPv4 TCP";
                            parsedPack.sourceAdress = $"{ (*pacResult.IPv4Header).SrcAddr} ";
                            parsedPack.destAdress = $"{(*pacResult.IPv4Header).DstAddr}";
                            break;
                        }
                    case 6:
                        {
                            parsedPack.typeHeader = "IPv6 TCP";
                            parsedPack.sourceAdress = $"{ (*pacResult.IPv6Header).SrcAddr} ";
                            parsedPack.destAdress = $"{(*pacResult.IPv6Header).DstAddr}";
                            break;
                        }
                }
            }
            catch(Exception e)
            {
                Log.SaveLog($" fail parse TCP packet ={e}");
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
            catch(Exception e)
            {
                Log.SaveLog($"fail when swap Big_Little endian ={e}");
                return 0;
            }
        }
    }
}
