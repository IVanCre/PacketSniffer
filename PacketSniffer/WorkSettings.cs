
namespace PacketSniffer
{
    public enum Func:int
    {
        skipPacket,
        addPacket,
        waitPacket,
        crash
    }

    public class WorkSettings
    {
       public int variantFunc;
       public int argument;
       public string filter;

        public void Inicialize (Func num, int arg,string filt)
        {
            variantFunc = (int)num;
            argument = arg;
            filter = filt;
        }

        public void Reset()
        {
            variantFunc = -1;
            argument = -1;
            filter = "";
        }
    }
}
