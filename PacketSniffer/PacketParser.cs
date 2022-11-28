using System;
using WinDivertSharp;
using System.Windows.Forms;
using System.Drawing;

namespace PacketSniffer
{
    public unsafe class PacketParser
    {
        public static  void ParseFromQueue( MainForm refF)// функ.обертка нужна, чтобы задача создавалсь не с пустыми аргументами, а в процессе работы
        {
            AllStructs.PacketNode nodePacket;
            try
            {
                for (; ; )
                {
                    if (!refF.queueOfCatchPacks.IsEmpty)
                    {
                        if (refF.queueOfCatchPacks.TryDequeue(out nodePacket))
                            ParsePacket(nodePacket);
                    }
                }
            }
            catch(Exception e)
            {
                MessageBox.Show($"Cant parse queue ={e}");
                Log.SaveLog($"Cant parse queue ={ e}");
            }
        }


        private static void ParsePacket(AllStructs.PacketNode nodePacket)//вытаскиваем данные из захваченного пакета
        {
            AllStructs.ParsedPacketData parsedPack = new AllStructs.ParsedPacketData();

            try
            {
                var pacResult = WinDivert.WinDivertHelperParsePacket(nodePacket.packet, nodePacket.readLenPacketBits);//возвращает все данные из перехваченного пакета
                parsedPack.direction = nodePacket.addr.Direction.ToString();
                parsedPack.dataLenBytes = (int)nodePacket.readLenPacketBits;//полезные данные


                if (pacResult.IPv4Header != null)
                {
                    if (pacResult.TcpHeader != null)
                    {
                        TcpPacketFuncs.ParsePacket(ref parsedPack,ref pacResult, 4);
                    }
                    else
                    if (pacResult.UdpHeader != null)
                    {
                        UdpPacketFuncs.ParsePacket(ref parsedPack, ref pacResult,4);
                    }
                }
                else if(pacResult.IPv6Header != null )
                {
                    if (pacResult.TcpHeader != null)
                    {
                        TcpPacketFuncs.ParsePacket(ref parsedPack, ref pacResult,6);
                    }
                    else
                    if (pacResult.UdpHeader != null)
                    {
                        UdpPacketFuncs.ParsePacket(ref parsedPack, ref pacResult,6);
                    }
                }
                else if (pacResult.IcmpV4Header != null)
                {
                    IcmpFuncs.ParsePacket(ref parsedPack, ref pacResult, 4);
                }
                else if(pacResult.IcmpV6Header != null)
                {
                    IcmpFuncs.ParsePacket(ref parsedPack, ref pacResult, 6);
                }
                else
                {
                    parsedPack.typeHeader = "Unknown packet ";
                }

                SendDataToForm(nodePacket.packetNum,parsedPack, nodePacket.addr, nodePacket.colorOfRow, nodePacket.mainFormRef);
            }
            catch (Exception e)
            {
                MessageBox.Show($"Failed parse packet ={e}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Log.SaveLog($"Failed parse packet ={e}");
            }
        }

        private static void SendDataToForm(int packetNum, AllStructs.ParsedPacketData fullPacket, WinDivertAddress addr, Color color, MainForm refF)
        {
            //все вызовы должны быть в исходном потоке! 
            try
            {
                lock (refF.dataGridView1)
                {
                    if (refF.dataGridView1 != null)
                    {
                        refF.dataGridView1.Invoke(new Action(
                           delegate ()
                           {
                               refF.packetList.Add(fullPacket);
                               refF.dataSet1.AllData.Rows.Add(new object[] { packetNum,
                                                                 new DateTime(addr.Timestamp).ToString($" HH:mm:ss.fffffK"),
                                                                     fullPacket.typeHeader,
                                                                     fullPacket.direction,
                                                                     fullPacket.sourceAdress,
                                                                     fullPacket.destAdress});
                               PaintRow(refF, color);
                           })//заливаем данные в таблицу формы
                           );
                    }
                }
            }
            catch (Exception e)
            {
                MessageBox.Show($"Invoke to main flow is Fail={e}");
                Log.SaveLog($"Invoke to main flow is Fail={e}");
            }
        }

        private static void PaintRow(MainForm refF, Color color)
        {
            if(refF.dataGridView1.Rows[refF.dataGridView1.Rows.Count - 1] !=null)
                refF.dataGridView1.Rows[refF.dataGridView1.Rows.Count - 1].DefaultCellStyle.BackColor = color;
        }


    }
}
