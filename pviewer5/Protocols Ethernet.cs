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
    public class EthernetH : H
    {
        public ulong DestMAC { get; set; }
        public ulong SrcMAC { get; set; }
        public uint TypeLen { get; set; }
        public override string headerdisplayinfo { get { return "Ethernet header"; } }


        public EthernetH(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.Ethernet;

            if (RemainingLength < 0xe) return;
            DestMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            SrcMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            TypeLen = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            // NEED TO HANDLE Q-TAGGED FRAMES
            RemainingLength -= 0xe;

            pkt.phlist.Add(this);
            pkt.Prots |= Protocols.Ethernet;

            pkt.SrcMAC = SrcMAC;
            pkt.DestMAC = DestMAC;

            if (QuickFilterTools.QFMAC.Exclude(DestMAC) || QuickFilterTools.QFMAC.Exclude(SrcMAC))
            {
                pkt.qfexcluded = true;
                return;
            }

            switch (TypeLen)
            {
                case 0x800: //L3Protocol = Protocols.IP4;
                    new IP4H(fs, pfh, pkt, ref RemainingLength);
                    break;
                case 0x806:
                    new ARPH(fs, pfh, pkt, ref RemainingLength);
                    break;
                case 0x8dd: // L3Protocol = Protocols.IPv6;
                    break;
                default:
                    break;
            }
        }
    }



}
