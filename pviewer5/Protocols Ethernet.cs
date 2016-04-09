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
        public MAC DestMAC { get; set; }
        public MAC SrcMAC { get; set; }
        public uint TypeLen { get; set; }
        public override string displayinfo { get { return "Ethernet header"; } }


        public EthernetH(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {
            if ((pkt.Len - i) < 0xe) return;
            DestMAC = (ulong)pkt.PData[i++] * 0x0010000000000 + (ulong)pkt.PData[i++] * 0x000100000000 + (ulong)pkt.PData[i++] * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            SrcMAC = (ulong)pkt.PData[i++]  * 0x0010000000000 + (ulong)pkt.PData[i++]  * 0x000100000000 + (ulong)pkt.PData[i++]  * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            TypeLen = (uint)pkt.PData[i++]  * 0x100 + (uint)pkt.PData[i++] ;

            // NEED TO HANDLE Q-TAGGED FRAMES
            
            // set generic header properties
            headerprot = Protocols.Ethernet;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.Ethernet;
            pkt.SrcMAC = SrcMAC;
            pkt.DestMAC = DestMAC;

            pkt.phlist.Add(this);

            switch (TypeLen)
            {
                case 0x800: //L3Protocol = Protocols.IP4;
                    new IP4H(fs, pfh, pkt, payloadindex);
                    break;
                case 0x806:
                    new ARPH(fs, pfh, pkt, payloadindex);
                    break;
                case 0x8dd: // L3Protocol = Protocols.IPv6;
                    break;
                default:
                    break;
            }
        }
    }



}
