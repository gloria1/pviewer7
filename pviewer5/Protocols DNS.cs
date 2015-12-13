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




    // must also handle dns over tcp see rfc 5966


    public class DNSRR : PVDisplayObject
    {
        public Packet mypkt;            // reference to packet that contains this RR, so we can access the name string data
        public uint NAME { get; set; }    // index into pkt.PData of beginning of NAME
        public uint TYPE { get; set; }
        public uint CLASS { get; set; }
        // fields after this do not exist for "question" rr, but do exist for "answers"
        public uint TTL { get; set; }
        public uint RDLENGTH { get; set; }
        public uint RDATA1 { get; set; }    // index into pkt.PData of beginning of first field of RDATA (how to resolve depends on TYPE)
        public uint RDATA2 { get; set; }
        public uint RDATA3 { get; set; }
        public uint RDATA4 { get; set; }    // index into pkt.PData of beginning of first field of RDATA (how to resolve depends on TYPE)
        public uint RDATA5 { get; set; }
        public uint RDATA6 { get; set; }
        public uint RDATA7 { get; set; }    // index into pkt.PData of beginning of first field of RDATA (how to resolve depends on TYPE)
        public string NAMEString { get; set; }   // returns string form of domain name at pkt.PData[pos], resolving compression and putting in dots for separators
        
        public override string displayinfo { get { return "DNS RR, Name = " + NAMEString; } }
        
        public void Advanceposovername(byte[] d, ref uint pos)
        {
            while (true)        // this loop moves pos forward to byte after name field; names end with either a label of zero length or a pointer to elsewhere in the dns message
            {
                if ((d[pos] & 0xc0) == 0xc0)  // if this is a pointer, 
                {
                    pos += 2;   // adjust pos to byte after pointer,
                    break;      // and break out of loop
                }
                else                // else this is a regular label entry
                {
                    if (d[pos] == 0)  // if the label length is zero,
                    {
                        pos++;              // move pos to after the zero length label
                        break;              // and exit the loop
                    }
                    else pos += (uint)(d[pos] + 1);     // else this is a regular label so adjust pos to byte after this label
                }
            }

        }

        string formnamestring()
        {
            uint pos = NAME;
            string d = "";
            uint t;
            
            if (mypkt.PData[pos] == 0) return "<root>"; // if NAME just points to a terminator, it is the root

            while (mypkt.PData[pos] != 0)
            {
                 t = mypkt.PData[pos];
                 switch (t & 0xc0)
                 {
                     case 0:     // name particle of length t, at t+1
                         if (d.Length != 0) d += ".";    // if we are here, then there is a non-zero-length label to add to the domain name, so put in a dot separator
                         d += System.Text.Encoding.Default.GetString(mypkt.PData, (int)pos + 1, (int)t);
                         pos += (t + 1);
                         break;
                     case 0xc0:  // this is a pointer to somewhere else in the RR
                         pos = (t & 0x3f) * 0x100 + (uint)mypkt.PData[pos + 1];
                         break;
                     default:    // this should never happen
                         MessageBox.Show("Invalid compressed domain name particle in DNS RR");
                         break;
                  }
            }
            return d;
        }

        public DNSRR(Packet pkt, ref uint pos, bool isquestion)    // if isquestion==true, process as a question entry (having only NAME, TYPE and CLASS fields)
        {
            mypkt = pkt;

            NAME = pos;

            Advanceposovername(pkt.PData, ref pos);

            TYPE = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;
            CLASS = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;

            if (isquestion) return;     // if this is a "question" record, there are no further fields

            TTL = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;
            RDLENGTH = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;
            NAMEString = formnamestring();

            switch (TYPE)
            {
                case 1:         // A - a host address
                    RDATA1 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    break;
                case 2:         // NS - an authoritative name server
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 5:         // CNAME - the canonical name for an alias
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 6:         // SOA - start of zone of authority
                    RDATA1 = pos;        // MNAME - name server that was the original or primary source of data for this zone
                    Advanceposovername(pkt.PData, ref pos);
                    RDATA2 = pos;        // RNAME - mailbox of person responsible for this zone
                    Advanceposovername(pkt.PData, ref pos);
                    RDATA3 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // SERIAL - version number of the original copy of the zone
                    RDATA4 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // REFRESH - time (seconds) before zone should be refreshed
                    RDATA5 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // RETRY - time (seconds) before a failed refresh should be retried
                    RDATA6 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // EXPIRE - upper limit on time (seconds) before zone is no longer authoritative 
                    RDATA7 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // MINIMUM - TTL that should apply to any RR from this zone
                    break;
                case 7:         // MB - mailbox domain name
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 8:         // MG - mail group member
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 9:         // MR - mail rename domain name
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 0x0a:         // NULL - a null RR
                    pos += RDLENGTH;
                    break;
                case 0x0b:         // WKS - well known service description
                    RDATA1 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // ADDRESS - 32 bit internet address
                    RDATA2 = (uint)pkt.PData[pos]; pos++;  // PROTOCOL - 8 bit IP protocol number
                    RDATA3 = pos;    // bitmap - bit position corresponds to port number, bit set indicates protocol supported on that port
                    pos += RDLENGTH - 5;
                    break;
                case 0x0c:         // PTR - domain name pointer
                    RDATA1 = pos; pos += RDLENGTH;
                    break;
                case 0x0d:         // HINFO - host information
                    RDATA1 = pos; pos += pkt.PData[pos];   // CPU - character string (first byte is length, no null terminator)
                    RDATA2 = pos; pos += pkt.PData[pos];   // OS - character string (first byte is length, no null terminator)
                    break;
                case 0x0e:         // MINFO - mailbox or mail list information
                    RDATA1 = pos;
                    while (pkt.PData[pos] > 0) pos++;
                    RDATA2 = pos;
                    while (pkt.PData[pos] > 0) pos++;
                    break;
                case 0x0f:         // MX - mail exchange
                    RDATA1 = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1];
                    RDATA2 = pos + 2;
                    pos += RDLENGTH;
                    break;
                case 0x10:         // TXT - text strings
                    RDATA1 = pos; pos += RDLENGTH;    // character strings (can be > 1) where first byte is length and no null terminators
                    break;
                case 3:         // MD - a mail destination (OBSOLETE per rfc 1035)
                case 4:         // MF - a mail forwarder (obsolete per rfc 1035) 
                default:
                    MessageBox.Show("Unhandled DNS RR Type");
                    break;
            }
        }
    }

    public class DNSRRList : PVDisplayObject
    {
        public List<DNSRR> Items { get; set; }

        public DNSRRList()
        {
            Items = new List<DNSRR>();
        }

        public override string displayinfo
        {
            get
            {
                return String.Format("DNS RR List {0:X4} Items", Items.Count);
            }
        }
    }


    public class DNSH : H
    {
        // define the fields of the header itself
        // OBSOLETE - NAME ENTRIES WILL BE INDICES INTO pkt.PData       public byte[] dnsdata { get; set; } // this will contain the raw bytes of the whole DNS message - name entries will consist of pointers into this array, name entries that contain pointers to other names in the dns header can be resolved
        public uint Len { get; set; }

        public uint ID { get; set; }
        public uint QR { get; set; }        // 0 is query, 1 is response
        public uint OpCode { get; set; }     // 0 = standard query (QUERY)
        // 1 = inverse query (IQUERY)
        // 2 = server status request (STATUS)
        // 3-15 reserved (per rfc 1035, maybe more defined in later rfcs?)
        public uint AA { get; set; }        // authoritative answer
        public uint TC { get; set; }        // truncation = 1 if this message was truncated
        public uint RD { get; set; }        // recursion desired - directs name server to pursue query recursively
        public uint RA { get; set; }        // recursion available
        public uint Z { get; set; }         // reserved per rfc 1035
        public uint RCode { get; set; }     // response codes:
        //  0 = no error
        //  1 = format error
        //  2 = server failure
        //  3 = name error
        //  4 = not implemented
        //  5 = refused
        //  6 = reserved per rfc 1035
        public uint QDCOUNT { get; set; }   // number of questions
        public uint ANCOUNT { get; set; }   // number of answers
        public uint NSCOUNT { get; set; }   // number of name server authority records
        public uint ARCOUNT { get; set; }   // number of additional records
        public List<DNSRRList> RRs { get; set; } // outer list is questions, answers, authorities, additionals

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                return String.Format("DNS header text {0:X4}", ID);
            }
        }

        public DNSH(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {
            Len = (uint)(pkt.phlist[pkt.phlist.Count() - 1]).payloadlen;

            // if not enough data remaining, return without reading anything 
            // note that we have not added the header to the packet's header list yet, so we are not leaving an invalid header in the packet
            if ((pkt.Len - i) < Len) return;

            ID = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            QR = ((uint)pkt.PData[i] & 0x80) / 0x80;
            OpCode = ((uint)pkt.PData[i] & 0x78) / 0x08;
            AA = ((uint)pkt.PData[i] & 0x04) / 0x04;
            TC = ((uint)pkt.PData[i] & 0x02) / 0x02;
            RD = ((uint)pkt.PData[i++] & 0x01);
            RA = ((uint)pkt.PData[i] & 0x80) / 0x80;
            Z = ((uint)pkt.PData[i] & 0x70) / 0x10;
            RCode = ((uint)pkt.PData[i++] & 0x000f);

            QDCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            ANCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            NSCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            ARCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];

            RRs = new List<DNSRRList>();
            RRs.Add(new DNSRRList());    // add empty list to containt the questions

            for (int ii = 0; ii < QDCOUNT; ii++) RRs[0].Items.Add(new DNSRR(pkt, ref i, true));


            //ffadfdadfadd
            // finish debugging reading individual packets
            // add sub tree display for dns packets
            //      make question and answer rrs a single list
            //      add variables to index the list for firstAN, firstNS, firstAR
            //      add datatemplate for dnsitem
            // create dns grouping logic - simply match ID fields



            RRs.Add(new DNSRRList());
            for (int ii = 0; ii < ANCOUNT; ii++) RRs[1].Items.Add(new DNSRR(pkt, ref i, false));
            RRs.Add(new DNSRRList());
            for (int ii = 0; ii < NSCOUNT; ii++) RRs[2].Items.Add(new DNSRR(pkt, ref i, false));
            RRs.Add(new DNSRRList());
            for (int ii = 0; ii < ARCOUNT; ii++) RRs[3].Items.Add(new DNSRR(pkt, ref i, false));

            if (i != pkt.Len) MessageBox.Show("Did Not Read DNS record properly?  i != pkt.Len");

            // set generic header properties
            headerprot = Protocols.DNS;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.DNS;

            // add header to packet's header list
            pkt.phlist.Add(this);
        }



    }

    public class DNSG : G
    {
        // define properties of a specific group here
        public uint LocalPort;  // the port that is not 0x35, whether it be sender or receiver (the ID may be enough to uniquely identify the group, but making the local port part of the key as well can't hurt (can it?)
        public uint ID;

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                string s = null;

                foreach (H h in L[0].phlist)
                    if (h.headerprot == Protocols.DNS)
                    {
                        s = ((DNSH)h).RRs[0].Items[0].NAMEString;
                        break;
                    }

                return "DNS Group text"
                        + ", Question Name " + s;
            }
        }

        public DNSG(Packet pkt)
            : base(pkt)
        {

            // note: base class constructor is called first (due to : base(pkt) above)


            // set group properties here
            ID = 0;

            foreach (H h in pkt.phlist)
                if (h.headerprot == Protocols.DNS)
                {
                    ID = ((DNSH)h).ID;
                    break;
                }

            if (pkt.SrcPort != 0x35) LocalPort = pkt.SrcPort;
            else LocalPort = pkt.DestPort;
        }

        public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

            // rules for membership in an DNS packet group:
            //      packet has DNS protocol present
            //      AND SrcPort matches
            //      AND ID matches

            // can assume GList.CanBelong has returned true

            DNSH dnsh = (DNSH)h;

            // can  assume CanBelongToThisType has returned true

            return ((dnsh.ID == ID) && ((pkt.SrcPort == LocalPort) || (pkt.DestPort == LocalPort)));

            // also set Complete = true if this packet completes group
            // not sure what the conditions are for a DNS group to be complete - have to look it up
        }

    }

    public class DNSGList : GList       // generic DNS of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }


        public DNSGList(string n) : base(n)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            headerselector = Protocols.DNS;
        }


        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null);     // any packet with a DNS header can belong to a DNS group
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new DNSG(pkt);     // any packet with a DNS header can start a DNS group
            else return null;       // return null if cannot start a group with this packet
        }
    }

}