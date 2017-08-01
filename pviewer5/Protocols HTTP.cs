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


 


    // http group is intended to comprise all traffic with a given url
    //  properties
    //      dns lookup(s)
    //      list of http messages
    //          header info - copy strings into httpg (at least for items we will filter on)
    //          data - httpg just has pointer into tcp byte stream
    //  criteria for can belong - port 80 sender or receiver
    //  packet processing - if "Belongs" is returning true, update the abobe group properties accordingly before returning
    //  
    // HOW TO HANDLE THAT HTTPG WILL INTERCEPT PACKET BEFORE TCPG SEES IT?
    //     CALL TCPG LOGIC WITHIN HTTPG??






    public class HTTPG : G
    {
        // define properties of a specific group here

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                return base.displayinfo + "HTTP Group text";
            }
        }

        public HTTPG(Packet pkt, GList parent)
            : base(pkt, parent)
        {

            // note: base class constructor is called first (due to : base(pkt) above)


            // set group properties here
            Type = GTypes.HTTP;
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



    public class HTTPGList : GList       // generic example of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }

        public HTTPGList(string n, PVDisplayObject parent)
            : base(n, parent)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.Generic;
            Type = GTypes.HTTP;
        }


        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return true;
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (true) return new HTTPG(pkt, this);     // replace "true" with test for other qualifications for this packet to start a new group
            else return null;       // return null if cannot start a group with this packet
        }
    }

}