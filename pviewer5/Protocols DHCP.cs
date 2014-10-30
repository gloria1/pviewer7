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

    public class DHCP4H : H       // generic example of a header class
    {
        // define the fields of the header itself
        public uint DHCP4OpCode { get; set; }
        public uint DHCP4HWType { get; set; }
        public uint DHCP4HWAddrLen { get; set; }
        public uint DHCP4Hops { get; set; }
        public uint DHCP4XID { get; set; }
        public uint DHCP4Secs { get; set; }
        public uint DHCP4Flags { get; set; }
        public uint DHCP4ClientIP4 { get; set; }
        public uint DHCP4YourIP4 { get; set; }
        public uint DHCP4ServerIP4 { get; set; }
        public uint DHCP4GatewayIP4 { get; set; }
        public ulong DHCP4ClientHWAddr { get; set; }   // lower order 8 bytes of HW address
        public ulong DHCP4ClientHWAddrHigh { get; set; }  // higher order 8 bytes of HW address
        public uint DHCP4Cookie { get; set; }

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string headerdisplayinfo
        {
            get
            {
                return String.Format("DHCP, XID {0:X4}, OpCode {1:X4}", DHCP4XID, DHCP4OpCode);
            }
        }

        public DHCP4H(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {
            // set protocol
            headerprot = Protocols.DHCP4;

            // if not enough data remaining, return without reading anything 
            // note that we have not added the header to the packet's header list yet, so we are not leaving an invalid header in the packet
            if (RemainingLength < 0xf0) return;

            // read in the header data
            DHCP4OpCode = (uint)fs.ReadByte();
            DHCP4HWType = (uint)fs.ReadByte();
            DHCP4HWAddrLen = (uint)fs.ReadByte();
            DHCP4Hops = (uint)fs.ReadByte();
            DHCP4XID = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            DHCP4Secs = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DHCP4Flags = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DHCP4ClientIP4 = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            DHCP4YourIP4 = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            DHCP4ServerIP4 = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            DHCP4GatewayIP4 = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            // read bytes of client hardware addrsess, handle variable length, handle fact that bytes are "left justified" within the 16 byte field
            int i = 0; DHCP4ClientHWAddrHigh = 0;
            while (i < ((int)DHCP4HWAddrLen - 8)) { DHCP4ClientHWAddrHigh = DHCP4ClientHWAddrHigh * 0x100 + (ulong)fs.ReadByte(); i++; }
            i = 0; DHCP4ClientHWAddr = 0;
            while (i < (int)DHCP4HWAddrLen) { DHCP4ClientHWAddr = DHCP4ClientHWAddr * 0x100 + (uint)fs.ReadByte(); i++; }
            fs.Seek(16 - DHCP4HWAddrLen, SeekOrigin.Current);

            fs.Seek(0xc0, SeekOrigin.Current);  // skip over the 192, or 0xc0, legacy BOOTP area

            DHCP4Cookie = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();

            // adjust RemainingLength as needed
            RemainingLength -= 0xF0;

            // add header to packet's header list
            pkt.phlist.Add(this);
            pkt.Prots |= Protocols.DHCP4;

        }
    }


        public class DHCP4G : G
        {
            // define properties of a specific group here
            public uint DHCP4XID;      // these are the header fields that define an DHCPv4 group

            // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
            public override string groupdisplayinfo
            {
                get
                {
                    MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                    IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
                    return String.Format("DHCP Group, XID {0:X4}, Packet Count = {1:X4}", DHCP4XID, L.Count());
                }
            }

            public DHCP4G(Packet pkt) : base(pkt)
            {

                // note: base class constructor is called first (due to : base(pkt) above)

                // set group properties here
                foreach (H h in pkt.phlist) if (h.headerprot == Protocols.DHCP4)
                    {
                        DHCP4XID = ((DHCP4H)h).DHCP4XID;
                        break;
                    }
            }

            public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
            {
                // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

                // rules for membership in an DHCP4 packet group:
                //      XID's match
                // can assume GList.CanBelong has returned true

                // for DHCPv4, need to study further for completion criteria, in the meantime, never set complete


                if ((DHCP4H)h != null) return (DHCP4XID == ((DHCP4H)h).DHCP4XID);
                else
                {
                    MessageBox.Show("Packet with DHCP4 protocol flag set but no DHCP4 header in phlist");   // this should never happen
                    return false;       // if we got this far, there was no DHCP4 header, despite the DHCP4 protocol flag being set
                }
            }

        }


    public class DHCP4GList : GList       // generic example of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }


        public DHCP4GList(string n) : base(n)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.DHCP4;
        }


        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null);  // if pkt has a DHCP4 header it can belong
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new DHCP4G(pkt);     // replace "true" with test for other qualifications for this packet to start a new group
            else return null;       // return null if cannot start a group with this packet
        }
    }

}