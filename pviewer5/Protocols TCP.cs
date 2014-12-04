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

        public Packet NextPktInStream = null;   // pointer to packet containing next bytes in stream

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



    // tcp group extensions
    //      method(s) to get data from the TCP stream by just indexing into the stream, without regard to packet boundaries
    //          each packet should have a pointer to the packet with the next bytes in its stream
    //          each group should have a flag indicating whether it has been sequenced yet
    //          method to retrieve n bytes starting at relative sequence r from direction d
    //              method arguments are
    //                  reference to byte array of size n where data shold be copied
    //                  pointer to packet to start at (can be null)
    //                      pointer is suggestion - if null or it turns out to be wrong, start search at first packet
    //              method returns pointer to packet with next byte after last one copied into array (to be used as suggestion for next call)
    
    //      profiling information
    //          each group should have a flag indicating whether it has been profiled yet
    //          do not profile until one of the profile properties is accessed
    //          profile items:
    //              flag no missing bytes in sequence numbering
    //              flag proper setup
    //              flag proper teardown
    //              nunber of duplicate packets present
    //              number of packets data received out of order
    //              number of keep alives used
    //              duratin of keep alives
    //              number of retransmissions
    //              other characteristics that may signal problems
    // 


    public class TCPG : G
    {
        // define properties of a specific group here
        public uint S1IP4;      // these are the header fields that define a TCP group
        public uint S1Port;     // S1 indicates the sender of the first packet observed
        public uint S2IP4;      // S2 indicates the destination of the first packet observed, i.e., the sender in the other direction
        public uint S2Port;

        public enum TCPGState { NotSequencedYet, NormalStart, SequenceFailed };
                    // NotsequencedYet is initial state, and means we have not yet seen first 3 packets
                    // NormalStart means we found first 3 packets have normal 3 step handshake
                    // SequenceFailed means we have seen at least 3 packets and they are not the normal 3 step handshake
        public TCPGState State;

        public OPL OPL1;   // ordered packet list 1 - by definition, this is the stream of packets from the sender of the first SYN packet, i.e., the initiator of the TCP conversation
        public OPL OPL2;

        public int NextPacketToAddToOPLs = 0;     // index into TCPG.L
        

        public class OPL   // OPL = ordered packet list - will be list of pointers to packets for one stream of the TCP session, in sequence number order
        {
            public TCPG mygroup;           // reference to TCP group that owns this OPL
            public bool initialized;        // set false at construction, only true if OPL gets initialized with a properly sequenced stream
            public ulong FirstAbsSeq;     // absolute sequence number of start of stream
            public ulong MaxAbsSeq;      // highest absolute sequence number observed
            public ulong CurrRelSeq;    // next byte to be copied 
            public uint CurrOPLI;      // index of item containing byte at CurrRelSeq
            public class item
            {
                public Packet pkt;     // reference to packet containing this chunk of the stream
                public ulong AbsSeqOfFirstByteInPacket;
            }

            public List<item> OL;

            public OPL(TCPG g)
            {
                mygroup = g;
                initialized = false;
                CurrRelSeq = 0;
                CurrOPLI = 0;
                OL = new List<item>();
            }

            public bool CopyBytes(ulong n, byte[] dest)
            {
                ulong NewCurrRelSeq = CurrRelSeq;   // local version of current location state
                uint NewCurrOPLI = CurrOPLI;       // the "official" versions are not updated unless all n bytes are successfully copied
                ulong bytescopied = 0;
                item i;
                ulong b;
                ulong offsetinpacket;
                ulong bytestocopythispacket;
                
                if (mygroup.State != TCPGState.NormalStart) return false;
                if (!initialized)
                    if (!mygroup.InitOPLs()) return false;      // if InitOPLs returns false, something else is wrong, so return false

                while (bytescopied < n)
                {
                    // if in the middle of a packet, copy more bytes from this packet
                    if (NewCurrOPLI < OL.Count)     // if cursor not at end of packet list
                    {
                        i = OL[(int)NewCurrOPLI];
                        offsetinpacket = NewCurrRelSeq - i.AbsSeqOfFirstByteInPacket - FirstAbsSeq;

                        if ((offsetinpacket >= 0) && (offsetinpacket < i.pkt.DataLen))     // and if next sequence number to copy falls within this packet
                        {
                            bytestocopythispacket = n - bytescopied;
                            if (bytestocopythispacket > i.pkt.DataLen - offsetinpacket)
                            {
                                bytestocopythispacket = i.pkt.DataLen - offsetinpacket;
                                NewCurrOPLI++;      // if this copy will reach end of packet, increment the OL index
                            }
                            for (b = 0; b < bytestocopythispacket; b++) dest[bytescopied + b] = i.pkt.Data[offsetinpacket + b];
                            NewCurrRelSeq += bytestocopythispacket; // increment 
                        }
                        else
                        {
                            MessageBox.Show("seq of next byte to read does not fall in this packet");
                            return false;
                        }
                    }
                    else
                    {
                        // else go to next packet
                        // if no more packets, get another one (return false if no more, or if cannot find next packet in sequence
                        while (NewCurrOPLI == OL.Count) if (!mygroup.AddPktToOPLs()) return false;  // if AddPktToOPLs returns false, there are no more packets, so this function should return false
                        while ((OL[(int)NewCurrOPLI].AbsSeqOfFirstByteInPacket - FirstAbsSeq) != NewCurrRelSeq)
                        {
                            if (!mygroup.AddPktToOPLs()) return false;     // if sequence number of next packet in list is not equal to the desired next sequence number, there must be a missing packet
                            // so we keep reading more packets until we find the next sequence number, or if we run out of packets return false
                        }
                    }
                
                }
                // if we got this far, the full n bytes have been copied, so update the "official" state
                CurrRelSeq = NewCurrRelSeq;
                CurrOPLI = NewCurrOPLI;
                return true;
            }

            public bool SetCurrPos(long n)
            {
                // fill in with logic to update state using same logic as CopyBytes above
                // after CopyBytes has been debugged
                // in the meantime, always return false as stub
                return false;
            }
                
        }

        public bool InitOPLs()
        {
            // check whether first 3 packets are normal handshake
            if (State != TCPGState.NormalStart) return false;
            
            // if so, set up OPL's
            OPL1.FirstAbsSeq = ((TCPH)(L[0].groupprotoheader)).SeqNo;
            OPL2.FirstAbsSeq = ((TCPH)(L[1].groupprotoheader)).SeqNo;

            return true;
        }

        
        
        public bool AddPktToOPLs()
        {
            OPL opl;
            TCPH newth, oplth;
            int opli;       // index into opl.OL where new packet is being considered for insertion
            OPL.item curritem, newitem;
            ulong curritemdatalen;

            // note the next two sequence numbers are "TCP sequence numbers", i.e., raw sequence numbers from TCP protocol, not converted for rollover and not converted to relative terms
            ulong nextabsseq;   // the next absolute sequence number expected after current OPL item
            ulong newseq;   // absolute sequence number of packet to be added

            bool maxseqhi, newseqhi;


		    //return false if no more packets
            if (this.NextPacketToAddToOPLs == L.Count) return false;

            newitem = new OPL.item();    
            newitem.pkt = L[this.NextPacketToAddToOPLs++];
            newth = (TCPH)(newitem.pkt.groupprotoheader);
            newseq = newth.SeqNo;

            // determine which OPL to add next packet to
            if (newth.SrcPort == S1Port) opl = OPL1; else opl = OPL2;

            opli = opl.OL.Count();

            if (opli == 0)      // if list is empty, just add the new packet
            {
                newitem.AbsSeqOfFirstByteInPacket = newseq;
                opl.OL.Add(newitem);
                return true;
            }

            // adjust newseq if has rolled over zero in  32 bit space
            newseq += opl.MaxAbsSeq & 0xffffffff00000000;
            maxseqhi = (opl.MaxAbsSeq & 0xffffffff) > 0x80000000;
            newseqhi = (newseq & 0xffffffff) > 0x80000000;
            if (maxseqhi && !newseqhi) newseq += 0x100000000;
            if (!maxseqhi && newseqhi) newseq -= 0x100000000;
            newitem.AbsSeqOfFirstByteInPacket = newseq;
            
            while (true)
            {
                curritem = opl.OL[opli - 1];
                oplth = (TCPH)curritem.pkt.groupprotoheader;
                curritemdatalen = curritem.pkt.DataLen;
                nextabsseq = oplth.SeqNo + curritemdatalen;

                if (newseq >= nextabsseq) break;
                opli--;     // if new packet does not fit here, back up the cursor to prior packet in opl
                if (opli < 0)   MessageBox.Show("TCP stream sequencing algorithm fail - we should never reach this state");
            }

            opl.OL.Insert(opli, newitem);


            return true;
        }



        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string groupdisplayinfo
        {
            get
            {
                MACConverterNumberOrAlias mc = new MACConverterNumberOrAlias();
                IP4ConverterNumberOrAlias ic = new IP4ConverterNumberOrAlias();
                return "TCP Group"
                            + ", Stream1 IP4 " + ic.Convert(S1IP4, null, null, null)
                            + String.Format(", Stream1 Port {0:X4}", S1Port)
                            + ", Stream2 IP4 " + ic.Convert(S2IP4, null, null, null)
                            + String.Format(", Stream2 Port {0:X4}", S2Port)
                            + String.Format(", Packets in Group = {0:X2}", L.Count())
                            + State;
            }
        }

        public TCPG(Packet pkt, H h) : base(pkt)
        {

            // note: base class constructor is called first (due to : base(pkt) above)

            TCPH th = (TCPH)h;

            // set group properties here

            S1IP4 = pkt.SrcIP4;
            S1Port = pkt.SrcPort;
            S2IP4 = pkt.DestIP4;
            S2Port = pkt.DestPort;

            // SET ADDITIONAL GROUP PROPERTIES AS NECESSARY
            OPL1 = new OPL(this);
            OPL2 = new OPL(this);
            State = TCPGState.NotSequencedYet;

        }

        public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group, also tests for normal start sequence of TCP group
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

            // rules for membership in an TCP packet group:
            //      packet is an IP4 packet (later handle ipv6 and other layer 3 protocols)
            //      all packets with same pair of IP/Port in source and destination (either direction)

            // can assume GList.CanBelong has returned true

            // also set Complete = true if this packet completes group
            
            if (((pkt.SrcIP4 == S1IP4) && (pkt.SrcPort == S1Port) && (pkt.DestIP4 == S2IP4) && (pkt.DestPort == S2Port))   // if source==source and dest==dest
                || ((pkt.SrcIP4 == S2IP4) && (pkt.SrcPort == S2Port) && (pkt.DestIP4 == S1IP4) && (pkt.DestPort == S1Port)))  // or source==dest and dest==source
            {

                if (State == TCPGState.NotSequencedYet)
                {
                    if (L.Count == 2)   // if this is the third packet, test for normal start sequence
                                        // if the first three packets match the "normal" sequence, set State = NormalStart
                                        // otherwise set State = SequenceFailed
                                        // in no case do we leave State as NotSequencedYet
                    {
                        TCPH th = (TCPH)(L[0].groupprotoheader);
                        if ((th.Flags & 0x12)==0x02)    // if SYN set and ACK not set in first packet
                        {
                            th = (TCPH)(L[1].groupprotoheader);
                            if (th.SrcPort == S2Port)       // and if second packet is from stream 2
                            {
                                if ((th.Flags & 0x12) == 0x12)    // and if SYN set and ACK set in second packet
                                {
                                    if (pkt.SrcPort == S1Port)      // and if this (the third) packet is from stream 1
                                    {
                                        if ((th.Flags & 0x12)==0x10)    // and if SYN not set and ACK set in third packet
                                        {
                                            State = TCPGState.NormalStart;  // then we have a normal start sequence
                                        }
                                    }
                                }
                            }
                        }
                        if (State != TCPGState.NormalStart) State = TCPGState.SequenceFailed;
                    }                        
                }
                return true;
            }
            else return false;
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

            if (h != null) return new TCPG(pkt, h);     // if pkt has a TCP header it can start a TCP group
            else return null;       // return null if cannot start a group with this packet
        }
    }


}