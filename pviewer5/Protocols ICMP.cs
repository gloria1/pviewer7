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


        public ICMPH(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {
            if ((pkt.Len - i) < 0x08) return;
            Type = (uint)pkt.PData[i++];
            Code = (uint)pkt.PData[i++];
            Checksum = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];

            switch (Type)
            {
                case 3:		// destination unreachable
                case 11:	// time exceeded
                case 4:		// source quench
                    Unused = (uint)pkt.PData[i++] * 0x1000000 + (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    break;
                case 12:	// parameter problem
                    Pointer = (uint)pkt.PData[i++];
                    Unused = (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    break;
                case 5:		// redirect
                    GatewayAddress = (uint)pkt.PData[i++] * 0x1000000 + (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    break;
                case 8:		// echo
                case 0:		// echo reply
                case 15:	// information request
                case 16:	// information reply
                    Identifier = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    SequenceNumber = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    break;
                case 13:	// timestamp
                case 14:	// timestamp reply
                    if ((pkt.Len - i) < 0x0c) return; 
                    OriginateTimestamp = (uint)pkt.PData[i++] * 0x1000000 + (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    ReceiveTimestamp = (uint)pkt.PData[i++] * 0x1000000 + (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    TransmitTimestamp = (uint)pkt.PData[i++] * 0x1000000 + (uint)pkt.PData[i++] * 0x10000 + (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
                    break;
                default:
                    break;
            }

            // set generic header utility properties
            headerprot = Protocols.ICMP;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.ICMP;

            pkt.phlist.Add(this);
        }
    }

}
