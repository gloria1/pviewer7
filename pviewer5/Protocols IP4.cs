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
    public class IP4H : H
    {
        public uint Ver { get; set; }
        public uint HdrLen { get; set; }
        public uint TOS { get; set; }
        public uint Len { get; set; }
        public uint Ident { get; set; }
        public uint DontFrag { get; set; }
        public uint MoreFrags { get; set; }
        public uint FragOffset { get; set; }
        public uint TTL { get; set; }
        public uint Prot { get; set; }
        public uint Checksum { get; set; }
        public uint SrcIP4 { get; set; }
        public uint DestIP4 { get; set; }
        public uint OptionLen { get; set; }

        public override string headerdisplayinfo
        {
            get
            {
                IP4ConverterNumberOrAlias c = new IP4ConverterNumberOrAlias();
                return String.Format("IPv4 header, Protocol = {0:X4}, Src IP = ", Prot)
                    + c.Convert(SrcIP4, null, null, null)
                    + ", Dest IP = "
                    + c.Convert(DestIP4, null, null, null);
            }
        }


        public IP4H(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {
            if ((pkt.Len - i) < 0x1) return;
            HdrLen = (uint)pkt.PData[i++] ;
            Ver = (HdrLen & 0xf0) / 16; // note we keep this value in number of 32 bit words
            HdrLen &= 0x0f;   // mask out the high 4 bits that contain the version
            if ((pkt.Len - i) < (4 * HdrLen)) return; // if not enough bytes, this is not a valid header

            TOS = (uint)pkt.PData[i++] ;
            Len = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            Ident = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            FragOffset = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            DontFrag = (FragOffset & 0x4000) / 0x4000;
            MoreFrags = (FragOffset & 0x2000) / 0x2000;
            FragOffset &= 0x1fff;
            TTL = (uint)pkt.PData[i++] ;
            Prot = (uint)pkt.PData[i++] ;
            Checksum = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            SrcIP4 = (uint)pkt.PData[i++]  * 0x01000000 + (uint)pkt.PData[i++]  * 0x00010000 + (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            DestIP4 = (uint)pkt.PData[i++]  * 0x01000000 + (uint)pkt.PData[i++]  * 0x00010000 + (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;

            OptionLen = (HdrLen * 4) - 0x14;
            i += OptionLen;

            // HANDLE OPTIONS

            // set generic header properties
            payloadlen = (int)(Len - HdrLen * 4);
            payloadindex = i;
            headerprot = Protocols.IP4;

            // set packet level convenience properties
            pkt.Prots |= Protocols.IP4;
            pkt.SrcIP4 = SrcIP4;
            pkt.DestIP4 = DestIP4;
            pkt.ip4hdr = this;

            // add to header list
            pkt.phlist.Add(this);
            
            if (QuickFilterTools.QFIP4.Exclude(DestIP4) || QuickFilterTools.QFIP4.Exclude(SrcIP4))
            {
                pkt.qfexcluded = true;
                return;
            }

            switch (Prot)
            {
                case 0x01: //L4Protocol = Protocols.ICMP;
                    new ICMPH(fs, pfh, pkt, i);
                    break;
                case 0x02: // L4Protocol = Protocols.IGMP;
                    break;
                case 0x03: // L4Protocol = Protocols.GGP;
                    break;
                case 0x06: //L4Protocol = Protocols.TCP;
                    new TCPH(fs, pfh, pkt, i);
                    break;
                case 0x11: // L4Protocol = Protocols.UDP;
                    new UDPH(fs, pfh, pkt, i);
                    break;

                default:
                    break;
            }
        }
    }


}