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
	public enum Protocols  { Generic, Ungrouped, Pcap, Ethernet, Wifi, IP4, ARP, IPv6, TCP, UDP, ICMP, IGMP, GGP, DHCPv4, BOOTP }

    public class PcapFileHdr
    {
        public uint magicnumber;    // "magic number" - see http://wiki.wireshark.org/Development/LibpcapFileFormat
        public uint versionmajor;
        public uint versionminor;
        public int gmttolocal;      // GMT to local correction
        public uint sigfigs;        // accuracy of timestamps
        public uint snaplen;        // max length of captured packets in bytes
        public uint datalink;       // datalink type

        public bool bigendian;      // true = a1 first, false = d4 first
        public uint nanores;        // 0 = microsecond resolution, 1 = nanosecond resolution

        private uint flip32(byte[] d, int i)
        {
            byte[] dflip = new byte[4];
            dflip[0] = d[3 + i];
            dflip[1] = d[2 + i];
            dflip[2] = d[1 + i];
            dflip[3] = d[0 + i];
            return BitConverter.ToUInt32(dflip, 0);
        }
        private uint flip16(byte[] d, int i)
        {
            byte[] dflip = new byte[2];
            dflip[0] = d[1 + i];
            dflip[1] = d[0 + i];
            return BitConverter.ToUInt16(dflip, 0);
        }
        public PcapFileHdr(FileStream fs)
        {

            byte[] d = new byte[24];

            fs.Read(d, 0, 24);

            bigendian = (d[0] == 0xa1 ? true : false);

            magicnumber = (bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
            versionmajor = (bigendian ? flip16(d, 4) : BitConverter.ToUInt16(d, 4));
            versionminor = (bigendian ? flip16(d, 6) : BitConverter.ToUInt16(d, 6));
            gmttolocal = (int)(bigendian ? flip32(d, 8) : BitConverter.ToUInt32(d, 8));
            sigfigs = (bigendian ? flip32(d, 12) : BitConverter.ToUInt32(d, 12));
            snaplen = (bigendian ? flip32(d, 16) : BitConverter.ToUInt32(d, 16));
            datalink = (bigendian ? flip32(d, 20) : BitConverter.ToUInt32(d, 20));

        }
    }


/*    public class DHCPv4Group : PktGroup
    {
        public uint DHCPv4XID;      // these are the header fields that define an DHCPv4 group

        public static ObservableCollection<PktGroup> Groups = new ObservableCollection<PktGroup>();    // list of packet groups assembled based on this protocol

        public DHCPv4Group()
        {
            Protocol = Protocols.DHCPv4;
        }

        public static bool GroupPacket(PcapPkt pkt)     // returns true if pkt assigned to a group, false if not
        {
            // rules for membership in an DHCPv4 packet group:
            //      XID's match
            // DHCPv4 group header specification members:
            //      DHCPv4XID

            DHCPv4Group newgroup;
            DHCPv4Header ph = (DHCPv4Header)(pkt.L5Hdr);

            if (pkt.L5Hdr.Protocol != Protocols.DHCPv4) return false;      // if packet does not have a header of this type, return false

            // check for membership in existing groups
            foreach (DHCPv4Group g in Groups)
            {
                if (g.Complete) continue;
                if (ph.DHCPv4XID == g.DHCPv4XID)   // if this packet belongs to g
                {
                    g.L.Add(pkt);                                                                   // then add packet to the group
                    g.Firsttime = (g.Firsttime < pkt.ph.time) ? g.Firsttime : pkt.ph.time;          // adjust group timestamps
                    g.Lasttime = (g.Lasttime < pkt.ph.time) ? pkt.ph.time : g.Lasttime;             // adjust group timestamps
                    // if (this completes group) g.Complete = true;                                 // for DHCPv4, need to study further for completion criteria, in the meantime, never set complete
                    return true;
                }
            }
            // else start a new group
            newgroup = new DHCPv4Group();
            newgroup.DHCPv4XID= ph.DHCPv4XID;
            // if (...................) newgroup.Complete = true;   // for DHCPv4, need to study further for completion criteria, in the meantime, never set complete

            newgroup.L.Add(pkt);
            Groups.Insert(0, newgroup);     // insert at begining of list, so that for future packets, search begins with most recent group
            return true;
        }
    }*/
/*	public class DHCPv4Header : Header
	{
		public uint DHCPv4OpCode { get; set; }
		public uint DHCPv4HWType { get; set; }
		public uint DHCPv4HWAddrLen { get; set; }
		public uint DHCPv4Hops { get; set; }
		public uint DHCPv4XID { get; set; }
		public uint DHCPv4Secs { get; set; }
        public uint DHCPv4Flags { get; set; }
        public ulong DHCPv4ClientIP { get; set; }
        public ulong DHCPv4YourIP { get; set; }
        public ulong DHCPv4ServerIP { get; set; }
        public ulong DHCPv4GatewayIP { get; set; }
        public ulong DHCPv4ClientHWAddr { get; set; }   // lower order 8 bytes of HW address
        public ulong DHCPv4ClientHWAddrHigh { get; set; }  // higher order 8 bytes of HW address
        public uint DHCPv4Cookie { get; set; }

		public DHCPv4Header(FileStream fs, ref uint RemainingLength, ref bool NotParsed)
		{
			Layer = 5;
			Protocol = Protocols.DHCPv4;
			if (RemainingLength < 0xf0) { NotParsed = true; return; }

            DHCPv4OpCode = (uint)fs.ReadByte();
            DHCPv4HWType = (uint)fs.ReadByte();
            DHCPv4HWAddrLen = (uint)fs.ReadByte();
            DHCPv4Hops = (uint)fs.ReadByte();
            DHCPv4XID = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            DHCPv4Secs= (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
			DHCPv4Flags = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DHCPv4ClientIP = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            DHCPv4YourIP= (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            DHCPv4ServerIP = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            DHCPv4GatewayIP = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            // read bytes of client hardware addrsess, handle variable length, handle fact that bytes are "left justified" within the 16 byte field
            int i = 0; DHCPv4ClientHWAddrHigh = 0;
            while (i < ((int)DHCPv4HWAddrLen - 8)) { DHCPv4ClientHWAddrHigh = DHCPv4ClientHWAddrHigh * 0x100 + (ulong)fs.ReadByte(); i++; }
            i = 0; DHCPv4ClientHWAddr = 0;
            while (i < (int)DHCPv4HWAddrLen) { DHCPv4ClientHWAddr = DHCPv4ClientHWAddr * 0x100 + (ulong)fs.ReadByte(); i++; }
            fs.Seek(16 - DHCPv4HWAddrLen, SeekOrigin.Current);

            fs.Seek(0xc0, SeekOrigin.Current);  // skip over the 192, or 0xc0, legacy BOOTP area

            DHCPv4Cookie = (uint)fs.ReadByte() * 0x000001000000 + (uint)fs.ReadByte() * 0x000000010000 + (uint)fs.ReadByte() * 0x000000000100 + (uint)fs.ReadByte();
            
			RemainingLength -= 0xf0;
		}

	}*/
    
 /* SPECIFIC PROTOCOL HEADERS AND GROUPS WILL BE SUB-CLASSES OF THE GENERIC HEADER AND GROUP CLASSES
 * GENERIC GROUP CLASS WILL HAVE THE GENERIC METHODS FOR GROUP MEMBERSHIP TESTING AND CREATION
 * GENERIC CLASSES WILL HAVE SUCH OTHER METHODS THAT THE SUBCLASSES ONLY NEED TO PROVIDE
 *    THE CODING SPECIFIC TO THEIR CLASS (AND THE PROPERTIES SPECIFIC TO THEIR CLASS)
*/

    public class H
    {
        public Protocols headerprot;
        public virtual string headerdisplayinfo { get { return "Generic header"; } }

        public H()          // need a parameter-less constructor for sublcasses to inhereit from ?????
        { }
        public H(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
        {
            // if header cannot be read properly, reset file position to start of header, reset RemainingLength, and return
            // do not add header to packet's header list, and do not call downstream header constructors

            // if header is parsed correctly,
            //  add it to pkt's header list
            //  determine next layer hheader (if any) and call its constructor

        }
    }
    public class G
    {
        public delegate bool belongs(Packet pkt);
        public delegate G startnewgroup(Packet pkt);

        public static List<startnewgroup> starterfnlist = new List<startnewgroup>();

        public belongs belongdelegate;
        public bool Complete = false;
        public DateTime FirstTime, LastTime;   // earliest and latest timestamp in this group

        public ObservableCollection<Packet> L { get; set; }  // list items are individual packets
        public virtual string groupdisplayinfo { get { return "Generic group"; } }

        public G()      // need parameter-less constructor needs to exist for sub-classes for some reason
        { }

        public G(Packet pkt)   // this generic constructor will run before the protocol-specific constructor does
        {
            if (pkt.phlist[0].GetType() != typeof(PcapH))
            {
                //when this is in WPF put up a message box telling user pacekt does not have a pcap header
                return;
            }
            PcapH ph = pkt.phlist[0] as PcapH;
            FirstTime = LastTime = ph.time;
            L = new ObservableCollection<Packet>();
            L.Add(pkt);
        }

        public static bool GroupPacket(Packet pkt, ObservableCollection<G> grouplist)     // first checks whether packet can be added to a group in protgrouptestorder
        {                                                                // then checks whether packet can start a new group of one of the protocols in protgrouptestorder
                                                                            // returns true if assigned to a group, true if a new group is created, otherwise false
            foreach (G g in grouplist)
            {
                if (g.Complete) continue;
                if (g.belongdelegate(pkt))
                {
                    PcapH ph = pkt.phlist[0] as PcapH;
                    g.L.Add(pkt);
                    g.FirstTime = (g.FirstTime < ph.time) ? g.FirstTime : ph.time;          // adjust group timestamps
                    g.LastTime = (g.LastTime < ph.time) ? ph.time : g.LastTime;             // adjust group timestamps
                    return true;
                }
            }

            G newgroup;
            foreach (startnewgroup sf in starterfnlist)     // try starter functions, if one succeeds then add new group to list and return true
            {
                if ((newgroup = sf(pkt)) != null)
                {
                    grouplist.Insert(0, newgroup);
                    return true;
                }
            }
            return false;                   // if we got this far, pkt does not belong to any group nor is it basis for a new group
        }
        public virtual bool Belongs(Packet pkt)                 // returns true if pkt belongs in this group, also turns Complete to true if this packet will complete the group
        {
            return true;
        }
        public static G StartNewGroup(Packet pkt)   // starts a new group if this packet can be the basis for a new group of this type
        {
            return new G(pkt);
        }
    }


    public class PcapH : H
    {    
        public uint datalink { get; set; }      // copy of datalink type from capture file
        public DateTime time { get; set; }
        public uint caplen { get; set; }         // length captured
        public uint len { get; set; }            // length on the wire

        public override string headerdisplayinfo { get { return "Pcap header"; } }

        public PcapH(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
        {
            uint timesecs, timeusecs;
            byte[] d = new byte[0x10];

            headerprot = Protocols.Pcap;

            if (RemainingLength < 0x10) return;     // if not enough bytes, return without parsing header

            datalink = pfh.datalink;
            fs.Read(d, 0, 0x10);
            RemainingLength -= 0x10;

            // timestamp is stored in file as 2 32 bit integers (per inspection of file and per http://wiki.wireshark.org/Development/LibpcapFileFormat)
            // first is time in seconds since 1/1/1970 00:00:00, GMT time zone
            // second is microseconds (or nanoseconds if fileheader nanores == 1)
            timesecs = (pfh.bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
            timeusecs = (pfh.bigendian ? flip32(d, 4) : BitConverter.ToUInt32(d, 4));
            time = new DateTime(timesecs * TimeSpan.TicksPerSecond + timeusecs * TimeSpan.TicksPerSecond / 1000000 / ((pfh.nanores == 1) ? 1000 : 1));

            caplen = (pfh.bigendian ? flip32(d, 8) : BitConverter.ToUInt32(d, 8));
            len = (pfh.bigendian ? flip32(d, 12) : BitConverter.ToUInt32(d, 12));

            RemainingLength = caplen;

            pkt.phlist.Add(this);
            
            switch (datalink)
            {
                case 1:     // ethernet
                    new EthernetH(fs, pfh, pkt, ref RemainingLength);
                    break;
                default:
                    break;
            }
        }

        public static uint flip32(byte[] d, int i)
        {
            byte[] dflip = new byte[4];
            dflip[0] = d[3 + i];
            dflip[1] = d[2 + i];
            dflip[2] = d[1 + i];
            dflip[3] = d[0 + i];
            return BitConverter.ToUInt32(dflip, 0);
        }
        public static uint flip16(byte[] d, int i)
        {
            byte[] dflip = new byte[2];
            dflip[0] = d[1 + i];
            dflip[1] = d[0 + i];
            return BitConverter.ToUInt16(dflip, 0);
        }
    }

    public class EthernetH : H
    {
        public ulong DestMAC { get; set; }
        public ulong SrcMAC { get; set; }
        public uint TypeLen { get; set; }
        public override string headerdisplayinfo { get { return "Ethernet header"; } }


        public EthernetH(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.Ethernet;

            if (RemainingLength < 0xe) return;
            DestMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            SrcMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            TypeLen = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            // NEED TO HANDLE Q-TAGGED FRAMES
            RemainingLength -= 0xe;

            pkt.phlist.Add(this);

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

    public class ARPH : H
    {
        public uint HWType { get; set; }
        public uint Prot { get; set; }
        public uint HWAddrLen { get; set; }
        public uint ProtAddrLen { get; set; }
        public uint Opn { get; set; }
        public ulong SenderHW { get; set; }
        public ulong SenderProt { get; set; }
        public ulong TargetHW { get; set; }
        public ulong TargetProt { get; set; }
        public override string headerdisplayinfo { get { return "ARP header"; } }


        public ARPH(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.ARP;

            if (RemainingLength < 0x8) return;
            HWType = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            Prot = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            HWAddrLen = (uint)fs.ReadByte();
            ProtAddrLen = (uint)fs.ReadByte();
            Opn = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            RemainingLength -= 0x8;

            if (RemainingLength < (2 * HWAddrLen + 2 * ProtAddrLen)) { fs.Seek(-0x8, SeekOrigin.Current); /*need to "unread" the first 8 bytes since this will not be a valid header*/ RemainingLength += 0x8; return; }

            // HANDLE OTHER ADDR LEN VARIATIONS
            if ((HWAddrLen != 6) || (ProtAddrLen != 4)) { fs.Seek(-0x8, SeekOrigin.Current); /*need to "unread" the first 8 bytes since this will not be a valid header*/ RemainingLength += 0x8; return; }

            SenderHW = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            SenderProt = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            TargetHW = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
            TargetProt = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();

            RemainingLength -= 0x14;
      
            pkt.phlist.Add(this);
        }
    }

    public class ARPG : G
    {
        public uint HWType;      // these are the header fields that define an ARP group
        public uint Prot;
        public ulong SenderHW;
        public ulong SenderProt;
        public ulong TargetProt;
        public override string groupdisplayinfo { get { return String.Format("ARP group, Count = {0}",L.Count); } }

        public ARPG(Packet pkt) : base(pkt)
        {
            belongdelegate = Belongs;
            ARPH arph = null;
            foreach (H ph in pkt.phlist) if (ph.GetType() == typeof(ARPH)) { arph = (ARPH)ph; break; }
            HWType = arph.HWType;
            Prot = arph.Prot;
            SenderHW = arph.SenderHW;
            SenderProt = arph.SenderProt;
            TargetProt = arph.TargetProt;

            if (SenderProt == TargetProt) Complete = true;   // if this is a gratuitous ARP, mark the group complete immediately
        }
        public override bool Belongs(Packet pkt)                 // returns true if pkt belongs to group
        {
            // rules for membership in an ARP packet group:
            //      the first packet found is included (it may be a reply, if the request occurred before the capture file)
            //      if the packet is a gratuitous ARP, group is immediately marked complete
            //      further packets will be included if they are a valid response to the first packet (i.e., sender == original target, and opcode == 2)
            // ARP group header specification members:
            //      HWType
            //      Prot
            //      SenderHW address
            //      SenderProt address
            //      TargetProt address

            ARPH arph = null;
            foreach (H ph in pkt.phlist) if (ph.headerprot == Protocols.ARP)       // find the ARP header
            {
                arph = (ARPH)ph;
                if ((arph.TargetHW == SenderHW) && (arph.TargetProt == SenderProt) && (arph.SenderProt == TargetProt))   // if this packet is a proper response to the original request....
                    if ((arph.HWType == HWType) && (arph.Prot == Prot) && (arph.Opn == 2))       //  ... and if the hardware type and protocol fields match, and opcode == 2 
                    {
                        Complete = true;                                            // then this packet completes the group
                        return true;                                                // return true
                    }
            }
            return false;   // if we reached this point, we did not find an ARP header, or this ARP header is not a match for this group
        }
        public new static G StartNewGroup(Packet pkt)      // starts a new group if this packet can be the basis for a new group of this type
        {
            foreach (H ph in pkt.phlist) if (ph.headerprot == Protocols.ARP) return new ARPG(pkt);
            return null;
        }
    }

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
        public ulong SrcIP { get; set; }
        public ulong DestIP { get; set; }
        public uint OptionLen { get; set; }
        public byte[] Options { get; set; }
        public override string headerdisplayinfo { get { return "IPv4 header"; } }


        public IP4H(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
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
            SrcIP = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
            DestIP = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();

            OptionLen = (HdrLen * 4) - 0x14;
            if (OptionLen > 0)
            {
                Options = new byte[OptionLen];
                fs.Read(Options, 0, (int)OptionLen);
            }

            // HANDLE OPTIONS

            RemainingLength -= HdrLen * 4;

            pkt.phlist.Add(this);

            pkt.SrcIP4 = SrcIP;
            pkt.DestIP4 = DestIP;

            if (QuickFilterTools.QFIP4.Exclude(DestIP) || QuickFilterTools.QFIP4.Exclude(SrcIP))
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
                    break;
                case 0x11: // L4Protocol = Protocols.UDP;
                    new UDPH(fs, pfh, pkt, ref RemainingLength);
                    break;

                default:
                    break;
            }
        }
    }

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


        public ICMPH(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
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
        }
    }

    public class UDPH : H
    {
        public uint SrcPort { get; set; }
        public uint DestPort { get; set; }
        public uint Len { get; set; }
        public uint Checksum { get; set; }
        public override string headerdisplayinfo { get { return "UDP header"; } }


        public UDPH(FileStream fs, PcapFileHdr pfh, Packet pkt, ref ulong RemainingLength)
        {
            headerprot = Protocols.UDP;

            if (RemainingLength < 0x8) return;
            SrcPort = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            DestPort = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            Len = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            Checksum = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
            RemainingLength -= 0x8;

            pkt.phlist.Add(this);
        }
    }

    public class UDPG : G
    {
        public ulong SrcIP;      // these are the header fields that define an UDP group
        public uint SrcPort;
        public ulong DestIP;
        public uint DestPort;
        public override string groupdisplayinfo { get { return "UDP group"; } }

        public UDPG(Packet pkt) : base(pkt)
        {
            belongdelegate = Belongs;
            UDPH udph = GetUDPHdr(pkt);
            IP4H iph = GetIP4Hdr(pkt);
            // do not test for nulls - presumption is if this constructor is being called, we have already passed a "CanStartAGroupWithThisPacket" test - if not, there is a bug

            SrcIP = iph.SrcIP;
            SrcPort = udph.SrcPort;
            DestIP = iph.DestIP;
            DestPort = udph.DestPort;
        }
        public override bool Belongs(Packet pkt)                 // returns true if pkt belongs to group
        {
            // rules for membership in a UDP packet group:
            //      packet is an IP4 packet (later handle ipv6 and other layer 3 protocols)
            //      all packets with same pair of IP/Port in source and destination (either direction)

            // UDP group header specification members:
            //      src ip (in ip header)
            //      src port (in udp header)
            //      dest ip (in ip header)
            //      dest port (in udp header)

            UDPH udph = GetUDPHdr(pkt);
            if (udph == null) return false;
            IP4H iph = GetIP4Hdr(pkt);
            if (iph == null) return false;

            return (   ((iph.SrcIP == SrcIP) && (udph.SrcPort == SrcPort) && (iph.DestIP == DestIP) && (udph.DestPort == DestPort))   // if source==source and dest==dest
                    || ((iph.SrcIP == DestIP) && (udph.SrcPort == DestPort) && (iph.DestIP == SrcIP) && (udph.DestPort == SrcPort)));  // or source==dest and dest==source
        }
        public new static G StartNewGroup(Packet pkt)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // all that's required to start a udp group is a udp header and an IP4 header
            if ((GetIP4Hdr(pkt) != null) && (GetUDPHdr(pkt) != null)) return new UDPG(pkt);
            return null;
        }
        public static UDPH GetUDPHdr(Packet pkt)
        {
    //                foreach (P.H ph in pkt.phlist) if (ph.headerprot == Protocols.UDP) return (UDP.H)ph;
            // deleted above for performance gain - code below assumes fixed location of header in stack
            // not sure how much actual performance is gained
            H ph;
            if (pkt.phlist.Count >= 4)
            {
                ph = pkt.phlist[3];
                if (ph.headerprot == Protocols.UDP) return (UDPH)ph;
            }
            return null;
        }
        public static IP4H GetIP4Hdr(Packet pkt)
        {
    //                foreach (P.H ph in pkt.phlist) if (ph.headerprot == Protocols.IP4) return (IP4.H)ph;
            // deleted above for performance gain - code below assumes fixed location of header in stack
            // not sure how much actual performance is gained
            H ph;
            if (pkt.phlist.Count >= 3)
            {
                ph = pkt.phlist[2];
                if (ph.headerprot == Protocols.IP4) return (IP4H)ph;
            }
            return null;
        }
    }




    public class Packet
    {
        public List<H> phlist { get; set; }
        public ulong SrcMAC = 0;
        public ulong DestMAC = 0;
        public ulong SrcIP4 = 0;
        public ulong DestIP4 = 0;

        public string packetdisplayinfo { get { return "Packet"; } }



        public byte[] data;
		public bool qfexcluded;		// true is packed was excluded due to quickfilter - can drop once we transition to simply deleting quickfilter'ed packets

        public Packet(FileStream fs, PcapFileHdr pfh)
        {
            ulong RemainingLength;
            phlist = new List<H>();

            RemainingLength = (ulong)fs.Length;    // need to parse pcap packet to determine RemainingLength for packet

            // instantiate pcap header - that constructor will start cascade of constructors for inner headers
            new PcapH(fs, pfh, this, ref RemainingLength);

            data = new byte[RemainingLength];
			fs.Read(data, 0, (int)RemainingLength);
        }
    }

 

    public class DisplaySettings : INotifyPropertyChanged
	{
		private bool displayaliases = false;
		private bool displayIP4inhex = true;

		public bool DisplayAliases { get { return displayaliases; } set { displayaliases = value; Notify(); } }
		public bool DisplayIP4InHex { get { return displayIP4inhex; } set { displayIP4inhex= value; Notify(); } }

		public event PropertyChangedEventHandler PropertyChanged;

		protected void Notify()
		{
			if (PropertyChanged != null)
				PropertyChanged(this, new PropertyChangedEventArgs(null));
		}

	}


	public partial class MainWindow : Window
	{

        public List<Packet> pkts = new List<Packet>();
        public List<Packet> exclpkts = new List<Packet>();
        public ObservableCollection<G> maingrouplist { get; set; }
        
        public static DataGrid PacketDG;    // copy of packet data grid reference, static so that other classes can refer to it

	// TEMPORARY - PROVISION FOR VIEWING QF EXLUDED PACKETS
		// WHEN NO LONGER NEEDED, ALSO DELETE
		//		CODE IN ETHER AND IP4 HEADER STATIC CONSTRUCTORS THAT CREATES THE EXTRA HF ENTRIES
		public static DataGrid ExclDG;    // copy of packet data grid reference, static so that other classes can refer to it
		
		public static DisplaySettings ds = new DisplaySettings();

		public MainWindow()
		{
            maingrouplist = new ObservableCollection<G>();

            // populate master list of protocols to try creating groups for
            G.starterfnlist.Add(UDPG.StartNewGroup);
            G.starterfnlist.Add(ARPG.StartNewGroup);

            InitializeComponent();

			grid.DataContext = this;
			//QFExclGrid.DataContext = qfexcluded;
			//PacketDG = PacketDataGrid;
			//ExclDG = QFExclGrid;

		}

		private void ChooseFile(object sender, RoutedEventArgs e)
		{
			PcapFileHdr pfh;
			OpenFileDialog dlg = new OpenFileDialog();
			Nullable<bool> result;
			FileStream fs;
			Packet pkt;

			dlg.Multiselect = false;
			dlg.InitialDirectory = "C:\\users\\csadmin\\skydrive\\capfiles\\";
			result = dlg.ShowDialog();

			if (result == true)
			{
				QuickFilterTools.QFMAC.ResetCounters();
				QuickFilterTools.QFIP4.ResetCounters();
				//foreach (PktSet set in setlist.sets) set.pkts.Clear();
				//qfexcluded.pkts.Clear();
				filename.Content = dlg.FileName;
				fs = new FileStream(dlg.FileName, FileMode.Open);
				pfh = new PcapFileHdr(fs);
				while (fs.Position < fs.Length)
				{
					pkt = new Packet(fs, pfh);
// NEXT LINE IS TEMPORARY - ONCE QUICKFILTER IS TRUSTED, PACKETS THAT ARE EXCLUDED SHOULD SIMPLY BE DESTROYED
					if (pkt.qfexcluded) exclpkts.Add(pkt);
					else pkts.Add(pkt);
				}

                foreach (Packet p in pkts) G.GroupPacket(p, maingrouplist);

				fs.Close();
			}
		}

		private void qfbutton(object sender, RoutedEventArgs e)
		{
			Window qfd = new QuickFilterDialog();
			qfd.ShowDialog();
		}
		private void mnmbutton(object sender, RoutedEventArgs e)
		{
			Window w1 = new MACNameMapDialog();
			w1.ShowDialog();
			CollectionViewSource.GetDefaultView(PacketDG.ItemsSource).Refresh();
			CollectionViewSource.GetDefaultView(ExclDG.ItemsSource).Refresh();
		}
		private void inmbutton(object sender, RoutedEventArgs e)
		{
			Window w1 = new IP4NameMapDialog();
			w1.ShowDialog();
			CollectionViewSource.GetDefaultView(PacketDG.ItemsSource).Refresh();
			CollectionViewSource.GetDefaultView(ExclDG.ItemsSource).Refresh();
		}
		private void displayaliastoggle(object sender, RoutedEventArgs e)
		{
			ds.DisplayAliases = (bool)displayaliascheckbox.IsChecked;
			CollectionViewSource.GetDefaultView(PacketDG.ItemsSource).Refresh();
			CollectionViewSource.GetDefaultView(ExclDG.ItemsSource).Refresh();
		}
		private void displayIP4inhextoggle(object sender, RoutedEventArgs e)
		{
			ds.DisplayIP4InHex = (bool)displayIP4inhexcheckbox.IsChecked;
			CollectionViewSource.GetDefaultView(PacketDG.ItemsSource).Refresh();
			CollectionViewSource.GetDefaultView(ExclDG.ItemsSource).Refresh();
		}
		private void showethertoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showetherfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
//			foreach (HeaderField h in HFDict[Protocols.Ethernet].Values) if (h.Basic) h.DGCol.Visibility = newvis;
//			foreach (HeaderField h in HFDictExcl[Protocols.Ethernet].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showarpbasictoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showarpbasicfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
//			foreach (HeaderField h in HFDict[Protocols.ARP].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showarpdetailtoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showarpdetailfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
//			foreach (HeaderField h in HFDict[Protocols.ARP].Values) if (!h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showIP4basictoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showIP4basicfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
//			foreach (HeaderField h in HFDict[Protocols.IP4].Values) if (h.Basic) h.DGCol.Visibility = newvis;
//			foreach (HeaderField h in HFDictExcl[Protocols.IP4].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showIP4detailtoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showIP4detailfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
//			foreach (HeaderField h in HFDict[Protocols.IP4].Values) if (!h.Basic) h.DGCol.Visibility = newvis;
		}
		private static void Executedtabulate(object sender, ExecutedRoutedEventArgs e)
		{
			ulong q;

			DataGrid dg = (DataGrid)e.Source;
			DataGridTextColumn col = (DataGridTextColumn)(dg.CurrentColumn);
			if (col == null) return;
//			string path = ((Binding)(col.Binding)).Path.Path;		// col.Binding is of type BindingBase - Path property does not exist in BindingBase, so had to cast to Binding - don't know if this will cause problems.....

	//		foreach (PcapPkt p in dg.ItemsSource) q = (ulong)(col.GetCellContent(p).GetValue();
		}
		private static void CanExecutetabulate(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}

	}
}
