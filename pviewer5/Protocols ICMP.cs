using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using Microsoft.Win32;



namespace pviewer5
{
    public class ICMPH : H
    {
        public uint Type { get; set; }
        public uint Code { get; set; }
        public uint Checksum { get; set; }
        public uint Unused { get; set; }
        public uint Pointer { get; set; }
        public ulong GatewayAddress { get; set; }
        public uint Identifier { get; set; }
        public uint SequenceNumber { get; set; }
        public ulong OriginateTimestamp { get; set; }
        public ulong ReceiveTimestamp { get; set; }
        public ulong TransmitTimestamp { get; set; }
        public override string headerdisplayinfo { get { return "ICMP header"; } }


        public ICMPH(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.ICMP;

            if (RemainingLength < 0x08) return;
            Type = (uint)fs.ReadByte();
            Code = (uint)fs.ReadByte();
            Checksum = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            RemainingLength -= 0x04;

            switch (Type)
            {
                case 3:		// destination unreachable
                case 11:	// time exceeded
                case 4:		// source quench
                    Unused = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    RemainingLength -= 0x04;
                    break;
                case 12:	// parameter problem
                    Pointer = (uint)fs.ReadByte();
                    Unused = (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    RemainingLength -= 0x04;
                    break;
                case 5:		// redirect
                    GatewayAddress = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    RemainingLength -= 0x04;
                    break;
                case 8:		// echo
                case 0:		// echo reply
                case 15:	// information request
                case 16:	// information reply
                    Identifier = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    SequenceNumber = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    RemainingLength -= 0x04;
                    break;
                case 13:	// timestamp
                case 14:	// timestamp reply
                    if (RemainingLength < 0x10) //need to "unread" the first 4 bytes since this will not be a valid header
                    { fs.Seek(-0x4, SeekOrigin.Current); RemainingLength += 0x4; return; }
                    OriginateTimestamp = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    ReceiveTimestamp = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    TransmitTimestamp = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                    RemainingLength -= 0x10;
                    break;
                default:
                    break;
            }

            pkt.phlist.Add(this);
            pkt.Prots |= Protocols.ICMP;
        }
    }

}
