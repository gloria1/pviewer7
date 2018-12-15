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
    public class PcapFile
    // ******************************************************************************************
    // NOTE: CURRENTLY ONLY HANDLING CASE OF A SINGLE SECTION WITH ENHANCED PACKET BLOCKS
    // SEE PCAPNG FORMAT NOTES IN ONENOTE IF/WHEN WE NEED TO GENERALIZE THIS
    // ******************************************************************************************
    {
        public enum PcapFileTypes { PcapOld, PcapNG };
        public PcapFileTypes Type;
        public PcapOldFileHeader FileHdrOld = null;
        public PcapNGFileHeader FileHdrNG = null;

        public PcapFile(FileStream fs)      // this will read header blocks up until the first packet block
        {
            uint initialbytes;

            initialbytes = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x00000100 + (uint)fs.ReadByte();
            fs.Seek(0, SeekOrigin.Begin);  // reset to beginning of file

            if (initialbytes == 0x0a0d0d0a)     // pcap-ng format
            {
                Type = PcapFileTypes.PcapNG;
                FileHdrNG = new PcapNGFileHeader(fs);
            }
            else
            {
                Type = PcapFileTypes.PcapOld;
                FileHdrOld = new PcapOldFileHeader(fs);
            }
        }


        public class PcapOldFileHeader
        {
            public uint MagicNumber;    // "magic number" - see http://wiki.wireshark.org/Development/LibpcapFileFormat
            public uint VersionMajor;
            public uint VersionMinor;
            public int GMTToLocal;      // GMT to local correction
            public uint SigFigs;        // accuracy of timestamps
            public uint SnapLen;        // max length of captured packets in bytes
            public uint DataLink;       // datalink type

            public bool Bigendian;      // true = a1 first, false = d4 first
            public uint Nanores;        // 0 = microsecond resolution, 1 = nanosecond resolution

            public PcapOldFileHeader(FileStream fs)
            {
                byte[] d = new byte[24];

                fs.Read(d, 0, 24);

                Bigendian = (d[0] == 0xa1 ? true : false);

                MagicNumber = (Bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
                VersionMajor = (Bigendian ? flip16(d, 4) : BitConverter.ToUInt16(d, 4));
                VersionMinor = (Bigendian ? flip16(d, 6) : BitConverter.ToUInt16(d, 6));
                GMTToLocal = (int)(Bigendian ? flip32(d, 8) : BitConverter.ToUInt32(d, 8));
                SigFigs = (Bigendian ? flip32(d, 12) : BitConverter.ToUInt32(d, 12));
                SnapLen = (Bigendian ? flip32(d, 16) : BitConverter.ToUInt32(d, 16));
                DataLink = (Bigendian ? flip32(d, 20) : BitConverter.ToUInt32(d, 20));
            }
        }


        // FOR INFO ON PCAP-NG FORMATION SEE https://github.com/pcapng/pcapng
        // also see summary in OneNote
        // ******************************************************************************************
        // NOTE: CURRENTLY ONLY HANDLING CASE OF A SINGLE SECTION WITH ENHANCED PACKET BLOCKS
        // SEE PCAPNG FORMAT NOTES IN ONENOTE IF/WHEN WE NEED TO GENERALIZE THIS
        // ******************************************************************************************

        public class PcapNGFileHeader
        {
            public List<SectionHeader> SHList;
            public SectionHeader CurrentSection;
            public Dictionary<uint, InterfaceDescription> IntDescDict;
            public DateTime TSBasis = new DateTime(1970, 1, 1);

            public PcapNGFileHeader(FileStream fs)
            {

                SHList = new List<SectionHeader>();
                CurrentSection = new SectionHeader(fs);     // first block must be a section header - read it
                SHList.Add(CurrentSection);
                // NOTE: INTERFACE DESCRIPTIONS SHOULD BE MOVED WITHIN THE SECTION HEADER
                // INTERFACE NUMBERS ARE LOCAL TO THE SECTION THEY ARE IN, AND (CAN) RESTART AT 0 FOR THE NEXT SECTION
                IntDescDict = new Dictionary<uint, InterfaceDescription>();   // as a dictionary because we will need to index it by interface ID number

                this.ReadBlocksUntilPacket(fs);
            }
            public void ReadBlocksUntilPacket(FileStream fs)         // read section header block and any other blocks until first packet block
            {
                uint blocktype;
                uint blocklen;

                do
                {
                    byte[] d = new byte[0x18];
                    fs.Read(d, 0, 0x18);
                    fs.Seek(-0x18, SeekOrigin.Current);  // rewind so packet constructor can read its blocktype
                    blocktype = (CurrentSection.bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
                    blocklen = (CurrentSection.bigendian ? flip32(d, 4) : BitConverter.ToUInt32(d, 4));

                    // if enhanced packet block, return
                    if (blocktype == 0x06) break;

                    // else handle other block types
                    switch (blocktype)
                    {
                        case 0x0a0d0d0a:    // new section header
                            CurrentSection = new SectionHeader(fs);
                            SHList.Add(CurrentSection);
                            break;
                        case 0x01:          // interface description block
                            IntDescDict.Add((uint)IntDescDict.Count, new InterfaceDescription(fs, CurrentSection.bigendian));
                            break;
                        case 0x02:          // "packet block"
                            MessageBox.Show(String.Format("PCAP-NG file type, unexpected block type 2 = packet block, which is obsolete"));
                            fs.Seek(blocklen, SeekOrigin.Current);
                            break;
                        case 0x03:          // "Simple packet block"
                            MessageBox.Show(String.Format("PCAP-NG file type, unhandled block type 3 = Simple Packet Block"));
                            fs.Seek(blocklen, SeekOrigin.Current);
                            break;
                        case 0x04:          // name resolution block
                            MessageBox.Show(String.Format("PCAP-NG file type, unhandled block type 4, Name Resolution Block"));
                            fs.Seek(blocklen, SeekOrigin.Current);
                            break;
                        case 0x05:          // interface statistics block
                            fs.Seek(blocklen, SeekOrigin.Current);
                            break;
                        default:           // unrecognized block type
                            MessageBox.Show(String.Format("PCAP-NG file type, unrecognized block type {0:X8} found", blocktype));
                            fs.Seek(blocklen, SeekOrigin.Current);
                            break;
                    }
                } while (fs.Position < fs.Length);  // continue loop unless we reached end of file
            }
        }


        public class SectionHeader
        {
            public uint ByteOrderMagic;
            public uint VersionMajor;
            public uint VersionMinor;
            public ulong SectionLength;
            public byte[] Options;
            public bool bigendian;
            public List<Option> OptionList;

            public SectionHeader(FileStream fs)
            {
                uint BlockType;
                uint BlockTotalLength;
                bool lastoption = false;
                byte[] d = new byte[24];
                fs.Read(d, 0, 24);

                bigendian = (d[8] == 0x1a ? true : false);

                BlockType = (bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
                BlockTotalLength = (bigendian ? flip32(d, 4) : BitConverter.ToUInt32(d, 4));
                ByteOrderMagic = (bigendian ? flip32(d, 8) : BitConverter.ToUInt32(d, 8));
                VersionMajor = (bigendian ? flip16(d, 0x0c) : BitConverter.ToUInt16(d, 0x0c));
                VersionMinor = (bigendian ? flip16(d, 0x0e) : BitConverter.ToUInt16(d, 0x0e));
                SectionLength = (bigendian ? flip64(d, 0x10) : BitConverter.ToUInt64(d, 0x10));

                OptionList = new List<Option>();
                // if BlockTotalLength is 0x1c, then there are no options
                if (BlockTotalLength == 0x1c) lastoption = true;
                while (!lastoption) OptionList.Add(new Option(fs, bigendian, ref lastoption));
                fs.ReadByte(); fs.ReadByte(); fs.ReadByte(); fs.ReadByte();     // eat 4 bytes, which is the block total length field repeated at the end of the block
            }
        }
        public class InterfaceDescription
        {
            public uint LinkType;
            public uint SnapLen;

            public string Comment = null;
            public string Device = null;
            public string DeviceDesc = null;
            public ulong IP4Addr = 0;
            public ulong IP4NetMask = 0;
            public ulong IP6AddrHigh = 0;
            public ulong IP6AddrLow = 0;
            public uint IP6PrefixLen = 0;
            public ulong MAC = 0;
            public ulong EUI = 0;
            public ulong InterfaceSpeed = 0;
            public ulong TSResolution = 6;      // default value is 6 if this option is not present in the interface description block
            // TSResol is an 8 bit value
            //      if most signif bit is 0, remaining bits indicate resolution as negative power of 10 (e.g., 6 means resolution is 10e-6 seconds, or 1 microsecond)
            //      if msb == 1, remaining bits indicate resolution as negative power of 2
            public ulong TimeZone = 0;
            public string Filter = null;
            public string OS = null;
            public ulong FCSLen = 0;
            public ulong TSOffset = 0;

            public ulong TSUnitsPerSecond = 1000000;    // default value is 1000000 if no tsresol option is present; will be re-calculated if that option is preesent

            public Option opt;

            public InterfaceDescription(FileStream fs, bool bigendian)
            {
                uint blocktype;
                uint blocktotallength;

                bool lastoption = false;
                byte[] d = new byte[24];
                fs.Read(d, 0, 16);

                blocktype = (bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
                blocktotallength = (bigendian ? flip32(d, 4) : BitConverter.ToUInt32(d, 4));
                LinkType = (bigendian ? flip16(d, 8) : BitConverter.ToUInt16(d, 8));
                // skip 2 bytes for reserved field
                SnapLen = (bigendian ? flip32(d, 0x0c) : BitConverter.ToUInt32(d, 0x0c));

                while (!lastoption)
                {
                    opt = new Option(fs, bigendian, ref lastoption);
                    switch (opt.Code)
                    {
                        case 0x00:      // last option
                            break;
                        case 0x01:      // comment
                            Comment = Encoding.UTF8.GetString(opt.Value, 0, opt.Value.Length);
                            break;
                        case 0x02:
                            Device = Encoding.UTF8.GetString(opt.Value, 0, opt.Value.Length);
                            break;
                        case 0x03:
                            DeviceDesc = Encoding.UTF8.GetString(opt.Value, 0, opt.Value.Length);
                            break;
                        case 0x04:
                            IP4Addr = (ulong)opt.Value[0] * 0x1000000 + (ulong)opt.Value[1] * 0x10000 + (ulong)opt.Value[2] * 0x100 + (ulong)opt.Value[3];
                            IP4NetMask = (ulong)opt.Value[4] * 0x1000000 + (ulong)opt.Value[5] * 0x10000 + (ulong)opt.Value[6] * 0x100 + (ulong)opt.Value[7];
                            break;
                        case 0x05:
                            IP6AddrHigh = (ulong)opt.Value[0] * 0x100000000000000 + (ulong)opt.Value[1] * 0x1000000000000 + (ulong)opt.Value[2] * 0x10000000000 + (ulong)opt.Value[3] * 0x100000000 + (ulong)opt.Value[4] * 0x1000000 + (ulong)opt.Value[5] * 0x10000 + (ulong)opt.Value[6] * 0x100 + (ulong)opt.Value[7];
                            IP6AddrLow = (ulong)opt.Value[8] * 0x100000000000000 + (ulong)opt.Value[9] * 0x1000000000000 + (ulong)opt.Value[10] * 0x10000000000 + (ulong)opt.Value[11] * 0x100000000 + (ulong)opt.Value[12] * 0x1000000 + (ulong)opt.Value[13] * 0x10000 + (ulong)opt.Value[14] * 0x100 + (ulong)opt.Value[15];
                            IP6PrefixLen = (uint)opt.Value[16];
                            break;
                        case 0x06:
                            MAC = (ulong)opt.Value[0] * 0x10000000000 + (ulong)opt.Value[1] * 0x100000000 + (ulong)opt.Value[2] * 0x1000000 + (ulong)opt.Value[3] * 0x10000 + (ulong)opt.Value[4] * 0x100 + (ulong)opt.Value[5];
                            break;
                        case 0x07:
                            EUI = (ulong)opt.Value[0] * 0x100000000000000 + (ulong)opt.Value[1] * 0x1000000000000 + (ulong)opt.Value[2] * 0x10000000000 + (ulong)opt.Value[3] * 0x100000000 + (ulong)opt.Value[4] * 0x1000000 + (ulong)opt.Value[5] * 0x10000 + (ulong)opt.Value[6] * 0x100 + (ulong)opt.Value[7];
                            break;
                        case 0x08:
                            InterfaceSpeed = (ulong)opt.Value[0] * 0x100000000000000 + (ulong)opt.Value[1] * 0x1000000000000 + (ulong)opt.Value[2] * 0x10000000000 + (ulong)opt.Value[3] * 0x100000000 + (ulong)opt.Value[4] * 0x1000000 + (ulong)opt.Value[5] * 0x10000 + (ulong)opt.Value[6] * 0x100 + (ulong)opt.Value[7];
                            break;
                        case 0x09:
                            TSResolution = (ulong)opt.Value[0];
                            if ((TSResolution & 0x80) != 0)     // if msb is 1, the remaining bits of this field is negative power of 2
                            {
                                TSUnitsPerSecond = 1;
                                TSUnitsPerSecond <<= (int)((TSResolution & 0x7f) - 1);
                            }
                            else                                // else it is a negative power of 10
                            {
                                TSUnitsPerSecond = 1;
                                for (ulong i = 0; i < TSResolution; i++) TSUnitsPerSecond *= 10;
                            }
                            break;
                        case 0x0a:
                            TimeZone = (ulong)opt.Value[0] * 0x1000000 + (ulong)opt.Value[1] * 0x10000 + (ulong)opt.Value[2] * 0x100 + (ulong)opt.Value[3];
                            break;
                        case 0x0b:
                            Filter = Encoding.UTF8.GetString(opt.Value, 0, opt.Value.Length);
                            break;
                        case 0x0c:
                            OS = Encoding.UTF8.GetString(opt.Value, 0, opt.Value.Length);
                            break;
                        case 0x0d:
                            FCSLen = (ulong)opt.Value[0];
                            break;
                        case 0x0e:
                            TSOffset = (ulong)opt.Value[0] * 0x100000000000000 + (ulong)opt.Value[1] * 0x1000000000000 + (ulong)opt.Value[2] * 0x10000000000 + (ulong)opt.Value[3] * 0x100000000 + (ulong)opt.Value[4] * 0x1000000 + (ulong)opt.Value[5] * 0x10000 + (ulong)opt.Value[6] * 0x100 + (ulong)opt.Value[7];
                            break;
                        default:
                            break;
                    }
                }
                fs.Seek(4, SeekOrigin.Current);     // eat 4 bytes, which is the block total length field repeated at the end of the block

            }
        }
        public class Option
        {
            public uint Code;
            public uint Length;
            public byte[] Value;

            public Option(FileStream fs, bool bigendian, ref bool lastoption)
            {
                long offset;
                byte[] d = new byte[4];
                fs.Read(d, 0, 4);

                Code = (bigendian ? flip16(d, 0) : BitConverter.ToUInt16(d, 0));
                Length = (bigendian ? flip16(d, 2) : BitConverter.ToUInt16(d, 2));
                Value = new byte[Length];
                fs.Read(Value, 0, (int)Length);
                offset = (4 - (Length & 3)) & 3;
                fs.Seek(offset, SeekOrigin.Current);    // option value is aligned to 32 bit boundary, Length indicates length of actual option data not including padding bytes, need to read through any padding bytes

                lastoption = (Code == 0);
            }
        }

        public static ulong flip64(byte[] d, int i)
        {
            byte[] dflip = new byte[8];
            dflip[0] = d[7 + i];
            dflip[1] = d[6 + i];
            dflip[2] = d[5 + i];
            dflip[3] = d[4 + i];
            dflip[4] = d[3 + i];
            dflip[5] = d[2 + i];
            dflip[6] = d[1 + i];
            dflip[7] = d[0 + i];
            return BitConverter.ToUInt64(dflip, 0);
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

    public class PcapH : H
    {
        public uint DataLink { get; set; }      // copy of datalink type from capture file
        public DateTime Time { get; set; }
        public uint CapLen { get; set; }         // length captured
        public uint Len { get; set; }            // length on the wire
        public uint NGBlockLen;                  // total block length, if this is a PcapNG packet (needed by Packet function so it can know how many bytes to read over after packet data section)

        public override string displayinfo { get { return base.displayinfo + "Pcap header, Timestamp: " + (Time.ToLocalTime()).ToString("yyyy-MM-dd HH:mm:ss.fffffff"); } }

        public PcapH(FileStream fs, PcapFile pcf, Packet pkt, uint i) : base(fs, pcf, pkt, i)
        {
            uint timesecs, timeusecs;
            uint timehigh, timelow;
            ulong time;
            PcapFile.InterfaceDescription thisif;
            uint pcaphdrlen;
            byte[] d = new byte[0x1c];

            if (pcf.Type == PcapFile.PcapFileTypes.PcapOld)   // if this is a plain pcap packet (not pcap ng)
            {
                headerprot = Protocols.PcapOld;

                DataLink = pcf.FileHdrOld.DataLink;
                fs.Read(d, 0, 0x10);

                // timestamp is stored in file as 2 32 bit integers (per inspection of file and per http://wiki.wireshark.org/Development/LibpcapFileFormat)
                // first is time in seconds since 1/1/1970 00:00:00, GMT time zone
                // second is microseconds (or nanoseconds if fileheader nanores == 1)
                timesecs = (pcf.FileHdrOld.Bigendian ? PcapFile.flip32(d, 0) : BitConverter.ToUInt32(d, 0));
                timeusecs = (pcf.FileHdrOld.Bigendian ? PcapFile.flip32(d, 4) : BitConverter.ToUInt32(d, 4));
                Time = new DateTime(timesecs * TimeSpan.TicksPerSecond + timeusecs * TimeSpan.TicksPerSecond / 1000000 / ((pcf.FileHdrOld.Nanores == 1) ? 1000 : 1));
                // adjust from unix time basis of 1970-01-01 to .NET time basis of 0001-01-01
                Time = Time.AddYears(1969);

                CapLen = (pcf.FileHdrOld.Bigendian ? PcapFile.flip32(d, 8) : BitConverter.ToUInt32(d, 8));
                Len = (pcf.FileHdrOld.Bigendian ? PcapFile.flip32(d, 12) : BitConverter.ToUInt32(d, 12));

                pcaphdrlen = 0x10;
                payloadindex = 0x10;
                payloadlen = (int)CapLen - 0x10;

                fs.Seek(-0x10, SeekOrigin.Current); // rewind so code below can read whole packet into pkt.PData
            }
            else
            {
                // this is a pcapng packet
                // currently only handling "enhanced packet block" type packets
                headerprot = Protocols.PcapNG;

                pcf.FileHdrNG.ReadBlocksUntilPacket(fs);    // read any non-packet blocks

                fs.Read(d, 0, 0x1c);

                NGBlockLen = (pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 4) : BitConverter.ToUInt32(d, 4));

                thisif = pcf.FileHdrNG.IntDescDict[(pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 8) : BitConverter.ToUInt32(d, 8))];

                DataLink = thisif.LinkType;
                timehigh = (pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 0x0c) : BitConverter.ToUInt32(d, 0x0c));
                timelow = (pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 0x10) : BitConverter.ToUInt32(d, 0x10));
                time = (ulong)timehigh * 0x100000000 + (ulong)timelow;
                Time = pcf.FileHdrNG.TSBasis;
                // adjust from unix time basis of 1970-01-01 to .NET time basis of 0001-01-01
                Time = Time.AddYears(1969);

                long factor = TimeSpan.TicksPerSecond / (long)thisif.TSUnitsPerSecond;
                time = (ulong)((long)time * factor);
                TimeSpan ts = new TimeSpan((long)time);

                Time = Time.Add(ts);
                CapLen = (pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 0x14) : BitConverter.ToUInt32(d, 0x14));
                Len = (pcf.FileHdrNG.CurrentSection.bigendian ? PcapFile.flip32(d, 0x18) : BitConverter.ToUInt32(d, 0x18));

                pcaphdrlen = 0x1c;
                payloadindex = 0x1c;
                payloadlen = (int)CapLen - 0x1c;

                fs.Seek(-0x1c, SeekOrigin.Current); // rewind so code below can read whole packet into pkt.PData
            }

            pkt.PData = new byte[pcaphdrlen + CapLen];
            pkt.Time = Time;
            pkt.Len = pcaphdrlen + CapLen;
            fs.Read(pkt.PData, 0, (int)(pcaphdrlen + CapLen));

            pkt.L.Add(this);
            pkt.Prots |= headerprot;
            pkt.ProtOuter = headerprot;

            switch (DataLink)
            {
                case 1:     // ethernet
                    new EthernetH(fs, pcf, pkt, payloadindex);
                    break;
                default:
                    break;
            }

        }
    }

}