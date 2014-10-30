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
    public class TCPH : H
    {
        // define the fields of the header itself

        public struct TCPOption
        {
            public uint Kind;       // encoded in 1 byte
            public uint Length;     // encoded in 1 byte, this is the length of option in bytes, including the kind and length bytes
            public uint[] Data;
        }

        public uint SrcPort { get; set; }
        public uint DestPort { get; set; }
        public uint SeqNo { get; set; }         // if SYN=1, initial sequence number
        // sequence number of first data byte will be this number +1
        // if SYN=0, sequence number of first byte of this segment
        public uint AckNo { get; set; }         // next sequence number receiver is expecting
        // first ACK sent by each end acknowledges the initial sequence number
        public uint DataOffset { get; set; }    // size of TCP header in 32 bit words
        public uint Flags { get; set; }     // bit 11-9 Reserved
        // bit 8    NS  ECN-nonce concealment protection (RFC 3540)
        // bit 7    CWR Congestion Window Reduced (RFC 3168)
        // bit 6    ECE ECN Echo (RFC 3168)
        // bit 5    URG Urgent pointer is significant
        // bit 4    ACK Acknowledgement field is significant
        // bit 3    PSH Push function - push buffered data to receiving application
        // bit 2    RST Reset the connection
        // bit 1    SYN Synchronize sequence numbers
        // bit 0    FIN No more data from sender
        public uint WindowSize { get; set; }
        public uint Checksum { get; set; }
        public uint UrgentPtr { get; set; } // offset from sequence number indicating last urgent data byte
        public TCPOption[] Options { get; set; }


        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string headerdisplayinfo
        {
            get
            {
                return String.Format("TCP Source Port {0:X4}, Dest Port {1:X4}", SrcPort, DestPort);
            }
        }

        public TCPH(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {
            uint temp;
            uint optionbytes;
            TCPOption thisoption;
            List<TCPOption> options = new List<TCPOption>();

            // set protocol
            headerprot = Protocols.TCP;

            // if not enough data remaining, return without reading anything 
            // note that we have not added the header to the packet's header list yet, so we are not leaving an invalid header in the packet
            if (RemainingLength < 0x14) return;

            // read in the fixed header data
            SrcPort = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DestPort = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            SeqNo = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            AckNo = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            temp = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DataOffset = temp / 0x1000;
            Flags = temp & 0xfff;
            WindowSize = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            Checksum = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            UrgentPtr = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();

            optionbytes = (DataOffset * 4) - 0x14;     // number of bytes of options plus any padding to get TCP header to 32 bit boundary
            if (RemainingLength < (optionbytes + 0x14)) { fs.Seek(-0x14, SeekOrigin.Current); return; }    // if not enough bytes to fill options fields, rewind and return

            for (uint i = 0; i < optionbytes; )
            {
                thisoption = new TCPOption();
                thisoption.Kind = (uint)fs.ReadByte(); i++;
                switch (thisoption.Kind)
                {
                    case 0:         // end of options list
                        thisoption.Length = 1;
                        fs.Seek((long)(optionbytes - i), SeekOrigin.Current);    // read any remaining padding bytes
                        i = optionbytes;
                        break;
                    case 1:         // NOP, just eat the byte
                        thisoption.Length = 1;
                        break;
                    case 2:         // maximum segment size, len is 4, segment size is 32 bits
                        thisoption.Length = (uint)fs.ReadByte();
                        thisoption.Data = new uint[1]; thisoption.Data[0] = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                        i += 3;
                        break;
                    case 3:         // window scale
                        thisoption.Length = (uint)fs.ReadByte();
                        thisoption.Data = new uint[1]; thisoption.Data[0] = (uint)fs.ReadByte();
                        i += 2;
                        break;
                    case 4:         // selective acknowledgement permitted
                        thisoption.Length = (uint)fs.ReadByte();
                        i++;
                        thisoption.Data = null;
                        break;
                    case 5:         // selective acknowledgement
                        thisoption.Length = (uint)fs.ReadByte();
                        if (thisoption.Length > 0x22) MessageBox.Show("TCP packet with bad Selective Acknowlegement option");
                        thisoption.Data = new uint[(thisoption.Length - 2) / 4];
                        for (int ii = 0; ii < (thisoption.Length - 2) / 4; ii++) thisoption.Data[ii] = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                        i += thisoption.Length - 1;
                        break;
                    case 8:         // timestamp and echo of previous timestamp
                        thisoption.Length = (uint)fs.ReadByte();
                        thisoption.Data = new uint[2];
                        thisoption.Data[0] = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                        thisoption.Data[1] = (uint)fs.ReadByte() * 0x1000000 + (uint)fs.ReadByte() * 0x10000 + (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
                        i += 9;
                        break;
                    case 0x0e:         // TCP alternate checksum request
                        thisoption.Length = (uint)fs.ReadByte();
                        thisoption.Data = new uint[1];
                        thisoption.Data[0] = (uint)fs.ReadByte();
                        i += 2;
                        break;
                    case 0x0f:         // TCP alternate checksum data
                        thisoption.Length = (uint)fs.ReadByte();
                        thisoption.Data = new uint[thisoption.Length];
                        for (int ii = 0; ii < thisoption.Length; ii++) thisoption.Data[ii] = (uint)fs.ReadByte();   // just naively read each byte into a uint - this option is considered "historic" and probably will never be encountered
                        i += thisoption.Length - 1;
                        break;
                    default:
                        MessageBox.Show("Unknown TCP header option type");
                        break;
                }
                options.Add(thisoption);
            }
            Options = new TCPOption[options.Count];
            // copy options into TCPH.Options
            for (int i = 0; i < options.Count; i++) Options[i] = options[i];

            RemainingLength -= optionbytes + 0x14;

            // add header to packet's header list
            pkt.phlist.Add(this);
            pkt.Prots |= Protocols.TCP;
            pkt.SrcPort = SrcPort;
            pkt.DestPort = DestPort;

            // determine which header constructor to call next, if any, and call it
            switch (1)
            {
                case 0x01:
                    break;

                default:
                    break;
            }
        }
    }

    public class TCPG : G
    {
        // define properties of a specific group here
        public uint SrcIP4;      // these are the header fields that define an TCP group
        public uint SrcPort;
        public uint DestIP4;
        public uint DestPort;

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string groupdisplayinfo
        {
            get
            {
                MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
                return "TCP Group"
                            + ", Source IP4 " + ic.Convert(SrcIP4, null, null, null)
                            + String.Format(", Source Port {0:X4}", SrcPort)
                            + ", Dest IP4 " + ic.Convert(DestIP4, null, null, null)
                            + String.Format(", Dest Port {0:X4}", DestPort)
                            + String.Format(", Packets in Group = {0:X2}", L.Count());
            }
        }

        public TCPG(Packet pkt) : base(pkt)
        {

            // note: base class constructor is called first (due to : base(pkt) above)


            // set group properties here

            SrcIP4 = pkt.SrcIP4;
            SrcPort = pkt.SrcPort;
            DestIP4 = pkt.DestIP4;
            DestPort = pkt.DestPort;
        }

        public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

            // rules for membership in an TCP packet group:
            //      packet is an IP4 packet (later handle ipv6 and other layer 3 protocols)
            //      all packets with same pair of IP/Port in source and destination (either direction)

            // can assume GList.CanBelong has returned true

            // also set Complete = true if this packet completes group

            return (((pkt.SrcIP4 == SrcIP4) && (pkt.SrcPort == SrcPort) && (pkt.DestIP4 == DestIP4) && (pkt.DestPort == DestPort))   // if source==source and dest==dest
                || ((pkt.SrcIP4 == DestIP4) && (pkt.SrcPort == DestPort) && (pkt.DestIP4 == SrcIP4) && (pkt.DestPort == SrcPort)));  // or source==dest and dest==source
        }

    }

    public class TCPGList : GList       // generic TCP of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }



        public TCPGList(string n) : base(n)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.TCP;
        }



        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null);     // if pkt has a TCP header it can belong to a TCP group
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new TCPG(pkt);     // if pkt has a TCP header it can start a TCP group
            else return null;       // return null if cannot start a group with this packet
        }
    }


}