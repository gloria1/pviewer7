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
        public byte[] Options { get; set; }

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


        public IP4H(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.IP4;

            if (RemainingLength < 0x1) return;
            HdrLen = (uint)fs.ReadByte();
            Ver = (HdrLen & 0xf0) / 16; // note we keep this value in number of 32 bit words
            HdrLen &= 0x0f;   // mask out the high 4 bits that contain the header length
            if (RemainingLength < (4 * HdrLen))  //need to "unread" the first 1 bytes since this will not be a valid header
            { fs.Seek(-0x1, SeekOrigin.Current); return; }

            TOS = (uint)fs.ReadByte();
            Len = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            Ident = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            FragOffset = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            DontFrag = (FragOffset & 0x4000) / 0x4000;
            MoreFrags = (FragOffset & 0x2000) / 0x2000;
            FragOffset &= 0x1fff;
            TTL = (uint)fs.ReadByte();
            Prot = (uint)fs.ReadByte();
            Checksum = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            SrcIP4 = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            DestIP4 = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();

            OptionLen = (HdrLen * 4) - 0x14;
            if (OptionLen > 0)
            {
                Options = new byte[OptionLen];
                fs.Read(Options, 0, (int)OptionLen);
            }

            // HANDLE OPTIONS

            RemainingLength -= HdrLen * 4;

            pkt.phlist.Add(this);
            pkt.Prots |= Protocols.IP4;

            pkt.SrcIP4 = SrcIP4;
            pkt.DestIP4 = DestIP4;

            if (QuickFilterTools.QFIP4.Exclude(DestIP4) || QuickFilterTools.QFIP4.Exclude(SrcIP4))
            {
                pkt.qfexcluded = true;
                return;
            }

            switch (Prot)
            {
                case 0x01: //L4Protocol = Protocols.ICMP;
                    new ICMPH(fs, pfh, pkt, ref RemainingLength);
                    break;
                case 0x02: // L4Protocol = Protocols.IGMP;
                    break;
                case 0x03: // L4Protocol = Protocols.GGP;
                    break;
                case 0x06: //L4Protocol = Protocols.TCP;
                    new TCPH(fs, pfh, pkt, ref RemainingLength);
                    break;
                case 0x11: // L4Protocol = Protocols.UDP;
                    new UDPH(fs, pfh, pkt, ref RemainingLength);
                    break;

                default:
                    break;
            }
        }
    }


}