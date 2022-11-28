using System;
using System.Windows.Forms;
using System.Threading;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;

namespace PacketSniffer
{



    public partial class MainForm : Form
    {
        WorkSettings workSet = new WorkSettings();

        CancellationTokenSource taskToken;
        WinDiverLogic divertLogic;

        public List<AllStructs.ParsedPacketData> packetList = new List<AllStructs.ParsedPacketData>();//для отображения данных перехваченных пакетов
        public ConcurrentQueue<AllStructs.PacketNode> queueOfCatchPacks = new ConcurrentQueue<AllStructs.PacketNode>();//для обработки перехваченных пакетов в том же порядке, что и перехватили
        bool pressStart = false;

        public MainForm()
        {
            InitializeComponent();
            dataGridView1.DataSource = dataSet1.AllData;//связываем представление и данные
        }

        private void SettingsPanelVisible_Click(object sender, EventArgs e)
        {
            switch (SettingsPanel.Visible)
            {
                case true:
                    {
                        SettingsPanel.Visible = false;
                        break;
                    }
                case false:
                    {
                        SettingsPanel.Visible = true;
                        break;
                    }
            }
        }

        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            VisibleTextBox("maskedTextBox0");
        }
        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            VisibleTextBox(null);
        }
        private void radioButton3_CheckedChanged(object sender, EventArgs e)
        {
            VisibleTextBox("maskedTextBox2");
        }
        private void radioButton4_CheckedChanged(object sender, EventArgs e)
        {
            VisibleTextBox(null);
        }
        private void VisibleTextBox(string nameBox)
        {
            foreach (Control c in SettingsPanel.Controls)
            {
                if (c.GetType() == typeof(MaskedTextBox))
                {
                    if (nameBox != null)
                    {
                        if (c.Name != nameBox)
                        {
                            ((MaskedTextBox)c).ReadOnly = true;
                            c.Text = "";
                        }
                        else
                        {
                            ((MaskedTextBox)c).ReadOnly = false;
                        }
                    }
                    else
                    {
                        ((MaskedTextBox)c).ReadOnly = true;
                        c.Text = "";
                    }
                }
            }
        }




        private bool InicializeWorkSettings()// завязано на имена нужных контролов
        {
            try
            {
                int arg = -1;

                int numFunc = comboBox1.SelectedIndex;
                if (numFunc < 3)
                {
                    arg = Convert.ToInt32(maskedTextBox0.Text);
                }

                if (FilterBox.Text == "")
                {
                    MessageBox.Show("Выберите фильтр !");
                    return false;
                }

                workSet.Inicialize((Func)numFunc, arg, FilterBox.Text);
            }
            catch(Exception e)
            {
                Log.SaveLog($" WorkSettings inic failure ={e}");
                return false;
            }
            return true;
        }


        private void Start_Click(object sender, EventArgs e)
        {
            try
            {
                string path = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + "Files\\Logs";
                if (!Directory.Exists(path))
                    Directory.CreateDirectory(path);




                if (!pressStart)
                {
                    dataSet1.Clear();

                    if (InicializeWorkSettings())
                    {
                        SettingsPanel.Visible = false;
                        taskToken = new CancellationTokenSource();
                        CancellationToken token = taskToken.Token;

                        if (divertLogic == null)
                            divertLogic = new WinDiverLogic();

                        divertLogic.Inic(token, workSet, FilterBox.Text, this);
                        divertLogic.StartCapture();// запускаем класс для обработки пакетов

                        button1.Text = "Pause";
                        pressStart = true;
                    }
                    else
                    {
                        MessageBox.Show("Work settings incorrect!");
                    }
                }
                else
                {
                    if (taskToken != null)
                    {
                        taskToken.Cancel();
                    }

                    workSet.Reset();
                    divertLogic.CloseCapture();

                    button1.Text = "Start";
                    pressStart = false;
                }
            }
            catch(Exception ex)
            {
                Log.SaveLog($" Button_start exception ={ex}");
            }
        }
        private void Clear_Click(object sender, EventArgs e)
        {
            try
            {
                dataSet1.Clear();
                packetList.Clear();

                AllStructs.PacketNode node;
                while (!queueOfCatchPacks.IsEmpty)
                {
                    queueOfCatchPacks.TryDequeue(out node);
                }

                DataBox.Text = "";
            }
            catch(Exception ex)
            {
                Log.SaveLog($" Clear_click exception ={ex}");
            }
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)//вытаскиваем данные для выделенной строки
        {
            try
            {
                int indexRow = e.RowIndex;
                if (indexRow <= packetList.Count - 1)
                {
                    DataBox.Text = "";

                    DataBox.Text += ($" Protocol Type  = {packetList[indexRow].typeHeader}") + Environment.NewLine;
                    DataBox.Text += ($" Source address = {packetList[indexRow].sourceAdress} : {packetList[e.RowIndex].sourcePort}") + Environment.NewLine;
                    DataBox.Text += ($" Destin address = {packetList[indexRow].destAdress} : {packetList[e.RowIndex].destPort}") + Environment.NewLine;
                    DataBox.Text += ($" Direction      = {packetList[indexRow].direction}") + Environment.NewLine;


                    switch (packetList[indexRow].typeHeader)
                    {
                        case "IPv4 TCP":
                            {
                                DataBox.Text += $" Header len   ={ Marshal.SizeOf(typeof(WinDivertSharp.TcpHeader))}" + Environment.NewLine;
                                DataBox.Text += $"\t  {packetList[indexRow].headerStruct.Window}... .... =CWR" + Environment.NewLine;
                                DataBox.Text += $"\t  ..{packetList[indexRow].headerStruct.Urg}. .... =Urget" + Environment.NewLine;
                                DataBox.Text += $"\t  ...{packetList[indexRow].headerStruct.Ack} .... =Acknowledgment" + Environment.NewLine;
                                DataBox.Text += $"\t  .... {packetList[indexRow].headerStruct.Psh}... =Push" + Environment.NewLine;
                                DataBox.Text += $"\t  .... .{packetList[indexRow].headerStruct.Rst}.. =Reset " + Environment.NewLine;
                                DataBox.Text += $"\t  .... ..{packetList[indexRow].headerStruct.Syn}. =Syn  " + Environment.NewLine;
                                DataBox.Text += $"\t  .... ...{packetList[indexRow].headerStruct.Fin} =Fin" + Environment.NewLine;
                                break;
                            }
                        case "IPv4 ICMP":
                            {
                                DataBox.Text += ($" ICMP code      = {packetList[indexRow].icmpByteCode}") + Environment.NewLine;
                                break;
                            }
                    }
                    DataBox.Text += ($" Leng of data = {packetList[indexRow].dataLenBytes}") + Environment.NewLine;
                }
            }
            catch(Exception ex)
            {
                Log.SaveLog($" Cant show data of cell ={ex}");
            }
        }

        private void MainForm_FormClosing(object sender, FormClosingEventArgs e)
        {

            MessageBox.Show($"Уверены, что закончили ? last error ={Marshal.GetLastWin32Error()}");
        }
    }
}
