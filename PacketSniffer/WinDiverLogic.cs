using System;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Threading;
using WinDivertSharp;
using WinDivertSharp.WinAPI;
using System.Windows.Forms;
using System.Drawing;

namespace PacketSniffer
{

    public class WinDiverLogic
    {
        CancellationToken token;
        WorkSettings workSet;
        IntPtr handle;
        string filter;
        MainForm mainFormRef;
        Random rand = new Random();
        static int goodErrorCode =997;// это код ERROR_IO_PENDING,  который показывает что операция выполняется и не нужно пока паниковать ("Выполняется перекрываемая операция ввода-вывода.")
        Color colorIndication = AllStructs.ColorIndication.Sniff;


        public void Inic(CancellationToken _token, WorkSettings _workSet, string _filter, MainForm reference)
        {
            token = _token;
            workSet = _workSet;
            filter = _filter;
            mainFormRef = reference;
        }

        public void StartCapture()
        {
            uint errorPos = 0;
            if (!WinDivert.WinDivertHelperCheckFilter(filter, WinDivertLayer.Network, out string errorMsg, ref errorPos))
            {
                MessageBox.Show($" Error in filter string at position: {errorPos}\n ErrMes: {errorMsg}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            errorPos = 0;

            WinDivertOpenFlags flag;
            switch(workSet.variantFunc)
            {
                case 4:
                    {
                        flag = WinDivertOpenFlags.Sniff;
                        break;
                    }
                default:
                    {
                        flag = WinDivertOpenFlags.None;//это позволит работать с пакетами в полную силу
                        break;
                    }
            }

            handle = WinDivert.WinDivertOpen(filter, WinDivertLayer.Network, 0, flag);

            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                MessageBox.Show("Invalid handle (ptr = ZERO). Failed to open.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                Log.SaveLog(" WinDivertOpen =false. handle== Zero");
            }
            else
            {
                WinDivert.WinDivertSetParam(handle, WinDivertParam.QueueLen, 16384);// Set everything to maximum values.
                WinDivert.WinDivertSetParam(handle, WinDivertParam.QueueTime, 8000);
                WinDivert.WinDivertSetParam(handle, WinDivertParam.QueueSize, 33554432);

                Task.Factory.StartNew(() =>
                {
                   RunDiversion();
                }, token);


                Task.Factory.StartNew(() =>
                {
                   ParseQueue();
                }, token);
            }
        }

        public void CloseCapture()
        {
            WinDivert.WinDivertClose(handle);
        }






        private async void RunDiversion()
        {
            var packet = new WinDivertBuffer();
            uint readLenPacketBits = 0;
            var addr = new WinDivertAddress();
            NativeOverlapped recvOverlapped;
            IntPtr recvEvent = IntPtr.Zero;

            uint recvAsyncIoLen = 0;
            uint sizeaddr = 0;
            int packetNum = 0;
            AllStructs.PacketNode node;
            int lastError=-1;

            try
            {
                do
                {
                    recvOverlapped = new NativeOverlapped();
                    recvEvent = Kernel32.CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);//указатель на объект события( сетевой пакет)



                    if (CatchPacket(recvEvent,
                            ref addr,
                                recvOverlapped,
                                packet,
                            ref readLenPacketBits,
                            ref recvAsyncIoLen))
                    {


                        node = new AllStructs.PacketNode();
                        PushToQueue(node, packet, readLenPacketBits, addr, packetNum);

                        sizeaddr = (uint)Marshal.SizeOf(typeof(WinDivertAddress));// в этой структуре есть указатель направления пакета, на основании этого направления, происходит инъекция пакета в нужный сетевой поток(вход/выход)
                        packetNum += 1;

                        switch (workSet.variantFunc)
                        {
                            case 0://skip not all
                                {
                                    if (rand.Next(100) >= workSet.argument) //чем выше аргумент, тем больше шансов дропнуть пакет
                                    {
                                        colorIndication = AllStructs.ColorIndication.Sniff;
                                        WinDivert.WinDivertSendEx(recvEvent, packet, readLenPacketBits, 0, ref addr, ref sizeaddr, ref recvOverlapped); //возврат пакета обратно в стек
                                    }
                                    else
                                        colorIndication = AllStructs.ColorIndication.Skipped;
                                    break;
                                }
                            case 1://add new
                                {
                                    for (int i = 0; i < workSet.argument; i++)
                                    {
                                        colorIndication = AllStructs.ColorIndication.Copy;
                                        WinDivert.WinDivertSendEx(recvEvent, packet, readLenPacketBits, 0, ref addr, ref sizeaddr, ref recvOverlapped);
                                    }
                                    break;
                                }
                            case 2://delay
                                {
                                    await Task.Run(() => { return Task.Delay(workSet.argument); });

                                    colorIndication = AllStructs.ColorIndication.Wait;
                                    WinDivert.WinDivertSendEx(recvEvent, packet, readLenPacketBits, 0, ref addr, ref sizeaddr, ref recvOverlapped);
                                    break;
                                }
                            case 3://crash tcp hexsum
                                {
                                    if (TcpPacketFuncs.DetectTcp(filter))
                                    {
                                        TcpPacketFuncs.CrashTcpHexSum(packet, readLenPacketBits);
                                        colorIndication = AllStructs.ColorIndication.CrashHexSum;
                                    }
                                    WinDivert.WinDivertSendEx(recvEvent, packet, readLenPacketBits, 0, ref addr, ref sizeaddr, ref recvOverlapped);
                                    break;
                                }
                            case 4://see
                                {
                                    colorIndication = AllStructs.ColorIndication.Sniff;
                                    WinDivert.WinDivertSendEx(recvEvent, packet, readLenPacketBits, 0, ref addr, ref sizeaddr, ref recvOverlapped);
                                    break;
                                }
                        }
                    }
                    Kernel32.CloseHandle(recvEvent);

                    lastError = Marshal.GetLastWin32Error();
                    if (lastError > -1)
                        Log.SaveLog($" WinError code ={lastError}");
                }
                while (!token.IsCancellationRequested);
            }
            catch(Exception e)
            {
                MessageBox.Show($"Execption when get/send packet:  {e}");
                Log.SaveLog($"RunDiversion fail ={e}");
            }
        }

        private void PushToQueue(AllStructs.PacketNode node, WinDivertBuffer packet,uint readLenPacketBits, WinDivertAddress addr,int packetNum  )
        {
            node.Create(packet, readLenPacketBits, addr, mainFormRef, colorIndication, packetNum);
            mainFormRef.queueOfCatchPacks.Enqueue(node);//добавление в очередь для послед. обработки
        }

        private  bool  CatchPacket(IntPtr recvEvent,ref WinDivertAddress addr, NativeOverlapped recvOverlapped, WinDivertBuffer packet,ref uint readLen,ref uint recvAsyncIoLen)//обработка выхваченного пакета из потока
        {
            bool rezult = false;
            addr.Reset();
            int lasterror = -1;
            try
            {
                recvOverlapped.EventHandle = recvEvent;
                if (!WinDivert.WinDivertRecvEx(handle, packet, 0, ref addr, ref readLen, ref recvOverlapped))// проверка  перехвата пакета
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error != goodErrorCode)
                    {
                        MessageBox.Show(string.Format($"Unknown IO error ID {error} while awaiting overlapped result.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error));
                        Kernel32.CloseHandle(recvEvent);
                    }

                    while (Kernel32.WaitForSingleObject(recvEvent, 100) == (uint)WaitForSingleObjectResult.WaitTimeout)//ждем, пока объект сам не посигналит о завершении
                        ;

                    rezult = Kernel32.GetOverlappedResult(handle, ref recvOverlapped, ref recvAsyncIoLen, false);
                    if (!rezult)//результат выполнения длит. опереции захвата пакета
                    {
                        MessageBox.Show("Failed to get overlapped result.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    readLen = recvAsyncIoLen;//длинна пакета, который мы захватили
                }
                Kernel32.CloseHandle(recvEvent);
                lasterror = Marshal.GetLastWin32Error();
            }
            catch(Exception e)
            {
                MessageBox.Show($"Exception when try catch packet ={e}");
                Log.SaveLog($" Catch packet fail/ ErrorCode ={e}");
            }

            return rezult;
        }

        private void ParseQueue()
        {
            PacketParser.ParseFromQueue(mainFormRef);
        }
    }
}
