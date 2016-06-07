﻿using System;
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
    [Serializable]
    public enum ExceptionLevels : uint
    {
        Zero = 0,
        One = 1,
        Two = 2
    }

    public struct ExceptionLevel
    {
        uint e;

        public void Ratchet(ExceptionLevel i)
        {
            if (i > e) e = i.e;
        }

        public override bool Equals(object o)
        {
            if (o == DependencyProperty.UnsetValue) return false;
            else return ((ExceptionLevel)o).e == e;
        }
        public override int GetHashCode() { return e.GetHashCode(); }
        public static implicit operator ExceptionLevel(uint i) { ExceptionLevel r = new ExceptionLevel(); r.e = i; return r; }
        public static ExceptionLevel operator +(ExceptionLevel a, ExceptionLevel b) { ExceptionLevel r = new ExceptionLevel(); r.e = a.e + b.e; return r; }
        public static ExceptionLevel operator *(ExceptionLevel a, ExceptionLevel b) { ExceptionLevel r = new ExceptionLevel(); r.e = a.e * b.e; return r; }
        public static ExceptionLevel operator &(ExceptionLevel a, ExceptionLevel b) { ExceptionLevel r = new ExceptionLevel(); r.e = a.e & b.e; return r; }
        public static ExceptionLevel operator |(ExceptionLevel a, ExceptionLevel b) { ExceptionLevel r = new ExceptionLevel(); r.e = a.e | b.e; return r; }
        public static bool operator ==(ExceptionLevel a, ExceptionLevel b) { return a.e == b.e; }
        public static bool operator !=(ExceptionLevel a, ExceptionLevel b) { return a.e != b.e; }
        public static bool operator <=(ExceptionLevel a, ExceptionLevel b) { return a.e <= b.e; }
        public static bool operator <(ExceptionLevel a, ExceptionLevel b) { return a.e < b.e; }
        public static bool operator >=(ExceptionLevel a, ExceptionLevel b) { return a.e >= b.e; }
        public static bool operator >(ExceptionLevel a, ExceptionLevel b) { return a.e > b.e; }

        public override string ToString() { return e.ToString(); }

    }

    public class PVDisplayObject
    {
        public bool isexpanded { get; set; } = false;
        public PVDisplayObject parent = null;
        private ExceptionLevel _e = 1;      // default value is 1, protocol or group specific logic can drop it to 0 if it affirmatively determines it is warranted
        public ExceptionLevel e
        {
            get { return _e; }
            set
            {
                _e = value;
                if (parent != null) parent.e.Ratchet(value);
            }
        }

        public virtual string displayinfo {
            get
            {
                string s = "";
                if (e > 0) s += "EXCEPTION LEVEL " + e.ToString() + "   ";
                return s;
            }
        }

        public virtual PVDisplayObject self { get { return this; } }
    }



    public class H : PVDisplayObject
    {
        // generic fields common to all headers
        public Protocols headerprot;    // protocol of this header, from Protocols enum
        public uint payloadindex;     // index into Packet.PData (relative to start of PData) of this header's payload
        public int payloadlen = -1;     // this will be set to the length of any payload encapsulated by this header's protocol
                                        // default value of -1 indicates that this header's protocol doesn't know anything about the size of its payload

        public H()          // need a parameter-less constructor for sublcasses to inherit from ?????
        { }
        public H(FileStream fs, PcapFile pcf, Packet pkt, uint i)      // i is index into pkt.PData of start of this header
        {
            parent = pkt;
            
            // if header cannot be read properly, 
            // do not add header to packet's header list, and do not call downstream header constructors, just return

            // first read protocol-specific properties

            // if header is parsed correctly,
            //  set the generic header properties
            //  set the packet-level convenience properties (e.g., pkt.ip4hdr)
            //  add it to pkt's header list
            //  determine next layer hheader (if any) and call its constructor

        }
    }

    public class G : PVDisplayObject, IEditableObject
    {
        public bool Complete = false;
        public DateTime FirstTime, LastTime;   // earliest and latest timestamp in this group

        public ObservableCollection<Packet> L { get; set; }  // list items are individual packets
        public ListCollectionView Lview;

        public virtual string displayinfo {
            get
            {
                string s = base.displayinfo;
                int i = 0;
                foreach (Packet p in L) if (p.FilterMatched) i++;
                s += String.Format("Total Count = {0}, Filtered Count = {1}", L.Count, i);
                return s;
            }
        }

        public bool AnyVisiblePackets
        {
            get
            {
                foreach (Packet p in L) if (p.FilterMatched) return true;
                return false;
            }
        }

        public G()      // need parameter-less constructor needs to exist for sub-classes for some reason
        { }

        public G(Packet pkt)   // this generic constructor will run before the protocol-specific constructor does
        {
            if (pkt.phlist[0].GetType() != typeof(PcapH))
            {
                // put up a message box telling user packet does not have a pcap header
                MessageBox.Show("Packet does not have a Pcap header???");
                return;
            }
            PcapH ph = pkt.phlist[0] as PcapH;
            FirstTime = LastTime = ph.Time;
            L = new ObservableCollection<Packet>();

            Lview = (ListCollectionView)CollectionViewSource.GetDefaultView(L);
            Lview.Filter = new Predicate<object>(GLFilter);

            L.Add(pkt);
            pkt.parent = this;
            ((ICollectionView)(CollectionViewSource.GetDefaultView(L))).Filter = delegate (object item) { return ((Packet)item).FilterMatched; };

            e = pkt.e;

        }

        public virtual bool Belongs(Packet pkt, H h)         // returns true if pkt belongs in this group, also turns Complete to true if this packet will complete the group
        {
            // h argument: the GroupPacket function can pass in a reference to a relevant protocol header, so Belongs does not have to search the header list every time it is called

            // can assume GList.CanBelong has returned true

            // also set Complete to true if this packet completes group

            // test pkt.Prots flags to quickly determine if this group's protocol is present

            return true;
        }

        public bool GLFilter(object p)
        {
            return ((Packet)p).FilterMatched;
        }

        // implement IEditableObject interface
        // see
        //  http://www.codeproject.com/Articles/61316/Tuning-Up-The-TreeView-Part
        //  http://drwpf.com/blog/2008/10/20/itemscontrol-e-is-for-editable-collection/
        public void BeginEdit() { }
        public void CancelEdit() { }
        public void EndEdit() { }

    }
    
    public class GList : PVDisplayObject, IEditableObject
    {
        public string name;
        public ObservableCollection<G> groups { get; set; }
        public ListCollectionView GLview;
        public virtual Protocols headerselector { get; set; }   // used by G.GroupPacket to pull the header for the relevant protocol out of the packet, to pass into the Belongs and StartNewGroup functions

        public override string displayinfo {
            get
            {
                string s = base.displayinfo;
                int i = 0;
                foreach (G g in groups) if (g.AnyVisiblePackets) i++;
                s += name;
                s += String.Format(", Total Group Count = {0}, Filtered Group Count = {1}", groups.Count, i);
                return s;
            }
        }
        
        public GList(string n)
        {
            name = n;

            groups = new ObservableCollection<G>();
            GLview = (ListCollectionView)CollectionViewSource.GetDefaultView(groups);
            GLview.Filter = new Predicate<object>(GGLFilter);

            ((ICollectionView)(CollectionViewSource.GetDefaultView(groups))).Filter = delegate (object item) { return ((G)item).AnyVisiblePackets; };

        }


        public bool GroupPacket(Packet pkt)         // first checks whether packet can be added to a group already in the list
        {                                           // then checks whether packet can start a new group of this type
            // returns true if assigned to a group, true if a new group is created, otherwise false

            H protoheader = null;
            foreach (H h in pkt.phlist) 
                if (h.headerprot == headerselector)
                {
                    protoheader = h;
                    break;
                }
            if (!CanBelong(pkt, protoheader)) return false;   // if packet cannot belong to group of this type, don't bother to iterate through group list
                   
            pkt.groupprotoheader = protoheader;
             
            foreach (G g in groups)
            {
                if (g.Complete) continue;
                if (g.Belongs(pkt, protoheader))
                {
                    PcapH ph = pkt.phlist[0] as PcapH;
                    g.L.Add(pkt);
                    pkt.parent = g;
                    g.e.Ratchet(pkt.e);
                    g.FirstTime = (g.FirstTime < ph.Time) ? g.FirstTime : ph.Time;          // adjust group timestamps
                    g.LastTime = (g.LastTime < ph.Time) ? ph.Time : g.LastTime;             // adjust group timestamps
                    return true;
                }
            }

            G newgroup = StartNewGroup(pkt, protoheader);
            if (newgroup == null) return false;
            else
            {
                groups.Insert(0, newgroup);
                return true;
            }
        }
        public virtual bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GroupPacket function can pass in a reference to a relevant protocol header (likely it's own protocol's header), so Belongs does not have to search the header list every time it is called
            return true;
        }
        public bool GGLFilter(object g)
        {
            return ((G)g).AnyVisiblePackets;
        }

        // implement IEditableObject interface
        // see
        //  http://www.codeproject.com/Articles/61316/Tuning-Up-The-TreeView-Part
        //  http://drwpf.com/blog/2008/10/20/itemscontrol-e-is-for-editable-collection/
        public void BeginEdit() { }
        public void CancelEdit() { }
        public void EndEdit() { }


        public virtual G StartNewGroup(Packet pkt, H h)   // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument: the GroupPacket function can pass in a reference to a relevant protocol header (likely it's own protocol's header), so StartNewGroup does not have to search the header list (since that was already done by GroupPacket for the Belongs calls)

            // test pkt.Prots flags to quickly determine if thsi group's protocol is present, return null if not

            // test other qualifications for starting a new group
            // return null if not eligible

            return new G(pkt);
        }
    }



    public class DisplayInfoMVC : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return ((PVDisplayObject)values[0]).displayinfo;
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    [Flags]
    public enum Protocols : ulong
    {
        Generic = 1,
        Ungrouped = 2,
        PcapOld = 4,
        PcapNG = 8,
        Ethernet = 0x10,
        Wifi = 0x20,
        IP4 = 0x40,
        ARP = 0x80,
        IP6 = 0x100,
        TCP = 0x200,
        UDP = 0x400,
        ICMP = 0x800,
        IGMP = 0x1000,
        GGP = 0x2000,
        DHCP4 = 0x4000,
        BOOTP = 0x8000,
        DNS = 0x10000
    }



    public class Packet : PVDisplayObject
    {
        public List<H> phlist { get; set; }

        // convenience properties to contain copies of commonly needed values,
        // so that other functions do not need to search through header list to find them
        public ulong SeqNo = 0; // absolute sequence number in packet file
        public Protocols Prots = Protocols.Generic;     // flags for protocols present in this packet
        public DateTime Time = new DateTime(0);
        public MAC SrcMAC = 0;
        public MAC DestMAC = 0;
        public IP4 SrcIP4 { get; set; } = 0;
        public IP4 DestIP4 = 0;
        public uint SrcPort = 0;       // UPD or TCP port, if any
        public uint DestPort = 0;
        public UDPH udphdr = null;
        public IP4H ip4hdr = null;
        public TCPH tcphdr = null;
        public H groupprotoheader { get; set; }     // packet group logic will set this to point to the header of the protocol relevant to that group type

        public override string displayinfo
        {
            get
            {
                string s = base.displayinfo;
                s += (Time.ToLocalTime()).ToString("yyyy-MM-dd HH:mm:ss.fffffff");
                s += "   Packet innermost header is: " + phlist[phlist.Count - 1].displayinfo;
                return s;
            }
        }

        public byte[] PData;
        public uint Len;

        public bool Visible { get; set; } = true;      // set based on application of filterset and exception level testing, feeds an ICollectionView.Filter

        public Packet() // empty constructor, constructs a packet with no data or headers
        {
            phlist = new List<H>();
            PData = new byte[0];
        }

        public Packet(FileStream fs, PcapFile pfh)
        {
            PcapH pch;

            phlist = new List<H>();
            Prots = 0;

            // instantiate pcap header - that constructor will start cascade of constructors for inner headers
            // PcapH constructor will also read all non-header data in
            pch = new PcapH(fs, pfh, this, 0);

            if (pfh.Type == PcapFile.PcapFileTypes.PcapNG)
                fs.Seek((long)(pch.NGBlockLen - 0x1c - pch.CapLen), SeekOrigin.Current);       // skip over any padding bytes, options and trailing block length field
        }

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;


    }



    /* BELOW NEEDS UPDATING TO INCORPORATE CHANGES ABOVE
     * 
        public class ExampleH : H       // generic example of a header class
        {
            // define the fields of the header itself
            public uint Prot { get; set; }

            // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
            public override string displayinfo
            {
                get
                {
                    return String.Format("Example header text {0:X4}", Prot);
                }
            }

            public ExampleH(FileStream fs, PcapFile pfh, Packet pkt, uint i)
            {

                // CONSTRUCTOR SHOULD ALSO INCLUDE PARAMETERS FOR ANY FIELDS THAT ARE NEEDED FROM ENCAPSULATING HEADERS
                // SO THAT THIS PROTOCOL'S FUNCTIONS NEVER HAVE TO SEARCH THE PHLIST FOR OTHER PROTOCOL'S HEADERS


                // if header cannot be read properly, 
                // do not add header to packet's header list, and do not call downstream header constructors, just return

                // first read protocol-specific properties

                // if header is parsed correctly,
                //  set the generic header properties
                headerprot = Protocols.Generic;
                payloadindex = i;
                payloadlen = (int)(pkt.Len - i);

                //  set the packet-level convenience properties (e.g., pkt.ip4hdr)
                pkt.Prots |= Protocols.Generic;

                //  add it to pkt's header list

                pkt.phlist.Add(this);


                // determine which header constructor to call next, if any, and call it
                switch (Prot)
                {
                    case 0x01: // ICMP
                        new ICMPH(fs, pfh, pkt, i);
                        break;

                    default:
                        break;
                }
            }
        }


        public class ExampleG : G
        {
            // define properties of a specific group here

            // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
            public override string displayinfo
            {
                get
                {
                    return "Example Group text";
                }
            }

            public ExampleG(Packet pkt) : base(pkt)
            {

                // note: base class constructor is called first (due to : base(pkt) above)


                // set group properties here

            }

            public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
            {
                // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

                // rules for membership in an Example packet group:
                //      packet is 

                // can assume GList.CanBelong has returned true

                // also set Complete = true if this packet completes group

                // first test whether packet has flag set for this protocol
                if (0 == (pkt.Prots & Protocols.Generic)) return false;

                return false;
            }

        }



        public class ExampleGList : GList       // generic example of a packet group class
        {
            // declare and initialize headerselector for this class of GList
            public override Protocols headerselector { get; set; }

            public ExampleGList(string n) : base(n)
            {
                // set headerselector to protocol header that G.GroupPacket should extract
                headerselector = Protocols.Generic;
            }


            public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
            {
                // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
                return true;
            }
            public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
            {
                // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

                if (true) return new ExampleG(pkt);     // replace "true" with test for other qualifications for this packet to start a new group
                else return null;       // return null if cannot start a group with this packet
            }
        }

        */

}