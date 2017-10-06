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

    public class UDPH : H
    {
        public uint SrcPort { get; set; }
        public uint DestPort { get; set; }
        public uint Len { get; set; }
        public uint Checksum { get; set; }
        public override string displayinfo
        {
            get
            {
                return base.displayinfo + String.Format("UDP Source Port {0:X4}, Dest Port {1:X4}", SrcPort, DestPort);
            }
        }

        public UDPH(FileStream fs, PcapFile pfh, Packet pkt, uint i) : base(fs, pfh, pkt, i)
        {

            if ((pkt.Len - i) < 0x8) return;
            SrcPort = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            DestPort = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            Len = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            Checksum = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];

            // set generic header properties
            headerprot = Protocols.UDP;
            payloadindex = i;
            payloadlen = (int)Len - 8;

            // set packet-level convenience properties
            pkt.Prots |= Protocols.UDP;
            pkt.ProtOuter = Protocols.UDP;
            pkt.udphdr = this;
            pkt.SrcPort = SrcPort;
            pkt.DestPort = DestPort;

            // add to packet header list
            pkt.L.Add(this);

            if ((SrcPort == 0x43) || (SrcPort == 0x44) || (DestPort == 0x43) || (DestPort == 0x44))     // DHCP v4
                new DHCP4H(fs, pfh, pkt, i);
            else if ((SrcPort == 0x35) || (DestPort == 0x35))                                           // DNS
                new DNSH(fs, pfh, pkt, i);

        }
    }

    public class UDPG : G
    {
        // define properties of a specific group here
        public IP4 SrcIP4;      // these are the header fields that define an UDP group
        public uint SrcPort;
        public IP4 DestIP4;
        public uint DestPort;

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                return base.displayinfo + "UDP Group"
                        + ", Source IP4 " + SrcIP4.ToString(false, true)
                        + String.Format(", Source Port {0:X4}", SrcPort)
                        + ", Dest IP4 " + DestIP4.ToString(false, true)
                        + String.Format(", Dest Port {0:X4}", DestPort)
                        + String.Format(", Packets in Group = {0:X2}", L.Count());
            }
        }

        public UDPG(Packet pkt, GList parent) : base(pkt, parent)
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

            // rules for membership in an UDP packet group:
            //      packet is an IP4 packet (later handle ipv6 and other layer 3 protocols)
            //      all packets with same pair of IP/Port in source and destination (either direction)

            // UDP group header specification members:
            //      src ip (in ip header)
            //      src port (in udp header)
            //      dest ip (in ip header)
            //      dest port (in udp header)

            // can assume GList.CanBelong has returned true

            // also set Complete = true if this packet completes group

            return (((pkt.SrcIP4 == SrcIP4) && (pkt.SrcPort == SrcPort) && (pkt.DestIP4 == DestIP4) && (pkt.DestPort == DestPort))   // if source==source and dest==dest
                        || ((pkt.SrcIP4 == DestIP4) && (pkt.SrcPort == DestPort) && (pkt.DestIP4 == SrcIP4) && (pkt.DestPort == SrcPort)));  // or source==dest and dest==source
        }

    }

    public class UDPGList : GList       // generic example of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }


        public UDPGList(string n, PVDisplayObject parent) : base(n, parent)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.UDP;
        }


        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null); // any packet with a UDP header can belong to a UDP group
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new UDPG(pkt, this);     // any packet with a UDP header can start a UDP group
            else return null;       // return null if cannot start a group with this packet
        }
    }


}
