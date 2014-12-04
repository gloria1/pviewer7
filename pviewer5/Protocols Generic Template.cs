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

    public class H
    {
        public Protocols headerprot;
        public virtual string headerdisplayinfo { get { return "Generic header"; } }

        public H()          // need a parameter-less constructor for sublcasses to inhereit from ?????
        { }
        public H(FileStream fs, PcapFile pcf, Packet pkt, ref ulong RemainingLength)
        {
            // if header cannot be read properly, reset file position to start of header, reset RemainingLength, and return
            // do not add header to packet's header list, and do not call downstream header constructors

            // if header is parsed correctly,
            //  add it to pkt's header list
            //  update Prots flags in packet
            //  determine next layer hheader (if any) and call its constructor

        }
    }

    public class G
    {
        public bool Complete = false;
        public DateTime FirstTime, LastTime;   // earliest and latest timestamp in this group

        public ObservableCollection<Packet> L { get; set; }  // list items are individual packets
        public virtual string groupdisplayinfo { get { return String.Format("Generic group, Count = {0}", L.Count); } }

        public G()      // need parameter-less constructor needs to exist for sub-classes for some reason
        { }

        public G(Packet pkt)   // this generic constructor will run before the protocol-specific constructor does
        {
            if (pkt.phlist[0].GetType() != typeof(PcapH))
            {
                // put up a message box telling user pacekt does not have a pcap header
                MessageBox.Show("Packet does not have a Pcap header???");
                return;
            }
            PcapH ph = pkt.phlist[0] as PcapH;
            FirstTime = LastTime = ph.Time;
            L = new ObservableCollection<Packet>();
            L.Add(pkt);
        }
        public virtual bool Belongs(Packet pkt, H h)         // returns true if pkt belongs in this group, also turns Complete to true if this packet will complete the group
        {
            // h argument: the GroupPacket function can pass in a reference to a relevant protocol header, so Belongs does not have to search the header list every time it is called

            // can assume GList.CanBelong has returned true

            // also set Complete to true if this packet completes group

            // test pkt.Prots flags to quickly determine if thsi group's protocol is present

            return true;
        }

    }
    
    public class GList
    {
        public string name;
        public ObservableCollection<G> groups { get; set; }
        public virtual Protocols headerselector { get; set; }   // used by G.GroupPacket to pull the header for the relevant protocol out of the packet, to pass into the Belongs and StartNewGroup functions

        public string glistdisplayinfo
        {
            get
            {
                return name + String.Format(", contains {0} groups", groups.Count());
            }
        }

        public GList(string n)
        {
            name = n;
            groups = new ObservableCollection<G>();
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
            
            foreach (G g in groups)
            {
                if (g.Complete) continue;
                if (g.Belongs(pkt, protoheader))
                {
                    PcapH ph = pkt.phlist[0] as PcapH;
                    g.L.Add(pkt);
                    pkt.groupprotoheader = protoheader;
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
        public virtual G StartNewGroup(Packet pkt, H h)   // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument: the GroupPacket function can pass in a reference to a relevant protocol header (likely it's own protocol's header), so StartNewGroup does not have to search the header list (since that was already done by GroupPacket for the Belongs calls)

            // test pkt.Prots flags to quickly determine if thsi group's protocol is present, return null if not

            // test other qualifications for starting a new group
            // return null if not eligible

            return new G(pkt);
        }
    }

    
    




    public class ExampleH : H       // generic example of a header class
    {
        // define the fields of the header itself
        public uint Prot { get; set; }

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string headerdisplayinfo
        {
            get
            {
                return String.Format("Example header text {0:X4}", Prot);
            }
        }

        public ExampleH(FileStream fs, PcapFile pfh, Packet pkt, ref ulong RemainingLength)
        {

            // CONSTRUCTOR SHOULD ALSO INCLUDE PARAMETERS FOR ANY FIELDS THAT ARE NEEDED FROM ENCAPSULATING HEADERS
            // SO THAT THIS PROTOCOL'S FUNCTIONS NEVER HAVE TO SEARCH THE PHLIST FOR OTHER PROTOCOL'S HEADERS


            // set protocol
            headerprot = Protocols.Generic;

            // if not enough data remaining, return without reading anything 
            // note that we have not added the header to the packet's header list yet, so we are not leaving an invalid header in the packet
            if (RemainingLength < 0x8) return;

            // read in the header data
            Prot = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();

            // adjust RemainingLength as needed
            RemainingLength -= 0x8;

            // add header to packet's header list
            pkt.phlist.Add(this);
            // set flag for presence of this protocol in the packet
            pkt.Prots |= Protocols.Generic;


            // determine which header constructor to call next, if any, and call it
            switch (Prot)
            {
                case 0x01: // ICMP
                    new ICMPH(fs, pfh, pkt, ref RemainingLength);
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
        public override string groupdisplayinfo
        {
            get
            {
                MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
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

}