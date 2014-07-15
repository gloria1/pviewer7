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
	public enum Protocols { Pcap, Ethernet, Wifi, IPv4, ARP, IPv6, TCP, UDP, ICMP, Other, NA }

	public class MACToMachineNameConverter : IValueConverter
	{
		static Dictionary<ulong, string> macnamemap = new Dictionary<ulong, string>();
		static MACToMachineNameConverter()
		{
			macnamemap.Add(0xc86000c667df, "win8fs 4");
			macnamemap.Add(0x5404a62bbb5c, "cnvssd7 3");
			macnamemap.Add(0x000e0cc442ff, "svr 2");
			macnamemap.Add(0xb0c74536471a, "buffalo ether");
			macnamemap.Add(0xb0c745364710, "buffalo 24g");
			macnamemap.Add(0xb0c745364715, "buffalo 5g");
		}

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			if (macnamemap.ContainsKey((ulong)value))
				return macnamemap[(ulong)value];
			else
				return String.Format("{0:x}", value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			throw new NotImplementedException();
		}
	}
	
	public class HeaderField				// HeaderField class - purpose is to contain all information that exists for a given header field
	{										// 	this includes:
		public string Label;				//			settings that control how it is displayed
		public Protocols Protocol;			//			a reference to the DataGridTextColumn that displays it
		public bool Basic;					//	The class for each protocol header type will include a static constructor that
		public DataGridTextColumn DGCol;	// 		1) creates a dictionary of HeaderField instances, one for each field in that protocol's header
		//		2) add that protocol's dictionary to the master dictionary which is declared (static) in MainWindow

		public HeaderField(string label, Protocols prot, bool basic, DataGrid dg, string bindingpath)
		{
			Label = label;
			Protocol = prot;
			Basic = basic;
			DGCol = new DataGridTextColumn();
			DGCol.Header = Label;
			DGCol.Binding = new Binding(bindingpath);
			DGCol.Binding.StringFormat = "x";
			DGCol.Visibility = Visibility.Hidden;
			dg.Columns.Add(DGCol);
		}
	}
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
		private uint nanores;        // 0 = microsecond resolution, 1 = nanosecond resolution

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
	public class Header						// Base class for protocol headers of all kinds
	{
		public uint Layer;          // 0 for PCAP, otherwise it's the OSI layer (e.g., 2 for Ether, 3 for IP, etc)
		public Protocols Protocol;
	}
	public class PcapPktHdr : Header
	{
		public uint datalink { get; set; }      // copy of datalink type from capture file
		public uint timesecs { get; set; }      // stored in file as 32 bit integer (per inspection of file and per http://wiki.wireshark.org/Development/LibpcapFileFormat)
		public uint timeusecs { get; set; }    // ditto
		public uint caplen { get; set; }         // length captured
		public uint len { get; set; }            // length on the wire

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
		public PcapPktHdr(FileStream fs, PcapFileHdr fh)
		{
			Layer = 0;
			Protocol = Protocols.Pcap;

			byte[] d = new byte[16];

			datalink = fh.datalink;
			fs.Read(d, 0, 16);

			timesecs = (fh.bigendian ? flip32(d, 0) : BitConverter.ToUInt32(d, 0));
			timeusecs = (fh.bigendian ? flip32(d, 4) : BitConverter.ToUInt32(d, 4));
			caplen = (fh.bigendian ? flip32(d, 8) : BitConverter.ToUInt32(d, 8));
			len = (fh.bigendian ? flip32(d, 12) : BitConverter.ToUInt32(d, 12));
		}
	}
	public class EthernetHeader : Header
	{
		public ulong DestMAC { get; set; }
		public static MACToMachineNameConverter dmconverter = new MACToMachineNameConverter();
		public ulong SrcMAC { get; set; }
		public uint TypeLen { get; set; }

		static EthernetHeader()          // static constructor, constructs header field dictionary and adds to master dictionary of header fields
		{
			Dictionary<string, HeaderField> HF = new Dictionary<string, HeaderField>();
			string s;

			s = "DestMAC"; HF.Add(s, new HeaderField(s, Protocols.Ethernet, true, MainWindow.PacketDG, "L2Hdr." + s));
			((Binding)(HF[s].DGCol.Binding)).Converter = dmconverter;
			s = "SrcMAC"; HF.Add(s, new HeaderField(s, Protocols.Ethernet, true, MainWindow.PacketDG, "L2Hdr." + s));
			s = "TypeLen"; HF.Add(s, new HeaderField(s, Protocols.Ethernet, true, MainWindow.PacketDG, "L2Hdr." + s));
			MainWindow.HFDict.Add(Protocols.Ethernet, HF);
		}

		public EthernetHeader(FileStream fs, ref uint RemainingLength, ref bool NotParsed)
		{
			Layer = 2;
			Protocol = Protocols.Ethernet;
			if (RemainingLength < 0xe) { NotParsed = true; return; }
			DestMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
			SrcMAC = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
			TypeLen = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
			// NEED TO HANDLE Q-TAGGED FRAMES
			RemainingLength -= 0xe;
		}
	}
	public class ARPHeader : Header
	{
		public uint ARPHWType { get; set; }
		public uint ARPProt { get; set; }
		public uint ARPHWAddrLen { get; set; }
		public uint ARPProtAddrLen { get; set; }
		public uint ARPOpn { get; set; }
		public ulong ARPSenderHW { get; set; }
		public ulong ARPSenderProt { get; set; }
		public ulong ARPTargetHW { get; set; }
		public ulong ARPTargetProt { get; set; }

		static ARPHeader()          // static constructor, constructs header field dictionary and adds to master dictionary of header fields
		{
			Dictionary<string, HeaderField> HF = new Dictionary<string, HeaderField>();
			string s;

			s = "ARPHWType"; HF.Add(s, new HeaderField(s, Protocols.ARP, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPProt"; HF.Add(s, new HeaderField(s, Protocols.ARP, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPHWAddLen"; HF.Add(s, new HeaderField(s, Protocols.ARP, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPProtAddLen"; HF.Add(s, new HeaderField(s, Protocols.ARP, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPOpn"; HF.Add(s, new HeaderField(s, Protocols.ARP, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPSenderHW"; HF.Add(s, new HeaderField(s, Protocols.ARP, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPSenderProt"; HF.Add(s, new HeaderField(s, Protocols.ARP, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPTargetHW"; HF.Add(s, new HeaderField(s, Protocols.ARP, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "ARPTargetProt"; HF.Add(s, new HeaderField(s, Protocols.ARP, true, MainWindow.PacketDG, "L3Hdr." + s));
			MainWindow.HFDict.Add(Protocols.ARP, HF);
		}

		public ARPHeader(FileStream fs, ref uint RemainingLength, ref bool NotParsed)
		{
			Layer = 3;
			Protocol = Protocols.ARP;
			if (RemainingLength < 0x8) { NotParsed = true; return; }
			ARPHWType = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
			ARPProt = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
			ARPHWAddrLen = (uint)fs.ReadByte();
			ARPProtAddrLen = (uint)fs.ReadByte();
			ARPOpn = (uint)fs.ReadByte() * 0x100 + (uint)fs.ReadByte();
			RemainingLength -= 0x8;

			if (RemainingLength < (2 * ARPHWAddrLen + 2 * ARPProtAddrLen)) { fs.Seek(-0x8, SeekOrigin.Current); /*need to "unread" the first 8 bytes since this will not be a valid header*/ RemainingLength += 0x8; NotParsed = true; return; }

			// HANDLE OTHER ADDR LEN VARIATIONS
			if ((ARPHWAddrLen != 6) || (ARPProtAddrLen != 4)) { fs.Seek(-0x8, SeekOrigin.Current); /*need to "unread" the first 8 bytes since this will not be a valid header*/ RemainingLength += 0x8; NotParsed = true; return; }

			ARPSenderHW = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
			ARPSenderProt = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
			ARPTargetHW = (ulong)fs.ReadByte() * 0x0010000000000 + (ulong)fs.ReadByte() * 0x000100000000 + (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();
			ARPTargetProt = (ulong)fs.ReadByte() * 0x000001000000 + (ulong)fs.ReadByte() * 0x000000010000 + (ulong)fs.ReadByte() * 0x000000000100 + (ulong)fs.ReadByte();

			RemainingLength -= 0x14;
		}
	}
	public class IPv4Header : Header
	{
		public uint IPv4Ver { get; set; }
		public uint IPv4HdrLen { get; set; }
		public uint IPv4TOS { get; set; }
		public uint IPv4Len { get; set; }
		public uint IPv4Ident { get; set; }
		public uint IPv4DontFrag { get; set; }
		public uint IPv4MoreFrags { get; set; }
		public uint IPv4FragOffset { get; set; }
		public uint IPv4TTL { get; set; }
		public uint IPv4Prot { get; set; }
		public uint IPv4Checksum { get; set; }
		public uint IPv4SrcIP { get; set; }
		public uint IPv4DestIP { get; set; }
		public uint IPv4OptionLen { get; set; }
		public byte[] IPv4Options { get; set; }

		static IPv4Header()          // static constructor, constructs header field dictionary and adds to master dictionary of header fields
		{
			Dictionary<string, HeaderField> HF = new Dictionary<string, HeaderField>();
			string s;

			s = "IPv4Ver"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4HdrLen"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4TOS"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4Len"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4Ident"; HF.Add(s, new HeaderField(s, Protocols.IPv4, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4DontFrag"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4MoreFrags"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4FragOffset"; HF.Add(s, new HeaderField(s, Protocols.IPv4, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4TTL"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4Prot"; HF.Add(s, new HeaderField(s, Protocols.IPv4, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4Checksum"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4SrcIP"; HF.Add(s, new HeaderField(s, Protocols.IPv4, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4DestIP"; HF.Add(s, new HeaderField(s, Protocols.IPv4, true, MainWindow.PacketDG, "L3Hdr." + s));
			s = "IPv4OptionLen"; HF.Add(s, new HeaderField(s, Protocols.IPv4, false, MainWindow.PacketDG, "L3Hdr." + s));
			MainWindow.HFDict.Add(Protocols.IPv4, HF);
		}

		public IPv4Header(FileStream fs, ref uint RemainingLength, ref bool NotParsed)
		{
			Layer = 3;
			Protocol = Protocols.IPv4;

			if (RemainingLength < 0x1) { NotParsed = true; return; }
			IPv4HdrLen = (uint)fs.ReadByte();
			IPv4Ver = (IPv4HdrLen & 0xf0) / 16; // note we keep this value in number of 32 bit words
			IPv4HdrLen &= 0x0f;   // mask out the high 4 bits that contain the header length
			if (RemainingLength < (4 * IPv4HdrLen)) { fs.Seek(-0x1, SeekOrigin.Current); /*need to "unread" the first 1 bytes since this will not be a valid header*/  NotParsed = true; return; }

			IPv4TOS = (uint)fs.ReadByte();
			IPv4Len = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
			IPv4Ident = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
			IPv4FragOffset = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
			IPv4DontFrag = (IPv4FragOffset & 0x4000) / 0x4000;
			IPv4MoreFrags = (IPv4FragOffset & 0x2000) / 0x2000;
			IPv4FragOffset &= 0x1fff;
			IPv4TTL = (uint)fs.ReadByte();
			IPv4Prot = (uint)fs.ReadByte();
			IPv4Checksum = (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
			IPv4SrcIP = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();
			IPv4DestIP = (uint)fs.ReadByte() * 0x01000000 + (uint)fs.ReadByte() * 0x00010000 + (uint)fs.ReadByte() * 0x0100 + (uint)fs.ReadByte();

			IPv4OptionLen = (IPv4HdrLen * 4) - 0x14;
			if (IPv4OptionLen > 0)
			{
				IPv4Options = new byte[IPv4OptionLen];
				fs.Read(IPv4Options, 0, (int)IPv4OptionLen);
			}

			// HANDLE OPTIONS

			RemainingLength -= IPv4HdrLen * 4;
		}
	}
	public class PcapPkt
	{
		public PcapPktHdr ph { get; set; }
		public uint RemainingLength;
		public bool NotParsed;
		public bool DoneParsing;
		public Protocols L2Protocol = Protocols.NA, L3Protocol = Protocols.NA, L4Protocol = Protocols.NA, L5Protocol = Protocols.NA;
		public Header L2Hdr { get; set; }
		public Header L3Hdr { get; set; }
		public Header L4Hdr { get; set; }
		public Header L5Hdr { get; set; }
		public byte[] Data;

		public PcapPkt(FileStream fs, PcapFileHdr fh)
		{
			ph = new PcapPktHdr(fs, fh);
			RemainingLength = (uint)ph.caplen;
			NotParsed = false;  // state indicator maintained by header constructors - if constructor is unable to fully parse the header
			//  it will set NotParsed to true AND constructor will reset file position to start of header
			DoneParsing = false;   // state indicator maintained in this constructor - set to true indicates there should be no further attempt to parse headers and all remaining packet data should just go into Data[]

			switch (ph.datalink)
			{
				case 1:         // ethernet
					L2Protocol = Protocols.Ethernet;
					L2Hdr = new EthernetHeader(fs, ref RemainingLength, ref NotParsed);
					if (NotParsed) L2Hdr = null;      // NotParsed==true means the ethernet header was not read
					else switch (((EthernetHeader)L2Hdr).TypeLen)
						{
							case 0x800: L3Protocol = Protocols.IPv4; break;
							case 0x806: L3Protocol = Protocols.ARP; break;
							case 0x8dd: L3Protocol = Protocols.IPv6; break;
							default: DoneParsing = true; break;
						}
					break;
				default:
					DoneParsing = true; break;
			}

			if (!DoneParsing) switch (L3Protocol)
				{
					case Protocols.ARP:
						L3Hdr = new ARPHeader(fs, ref RemainingLength, ref NotParsed);
						if (NotParsed) L3Hdr = null;      // NotParsed==true means the header was not read
						DoneParsing = true;
						break;
					case Protocols.IPv4:
						L3Hdr = new IPv4Header(fs, ref RemainingLength, ref NotParsed);
						if (NotParsed) L3Hdr = null;      // NotParsed==true means the header was not read
						else switch (((IPv4Header)L3Hdr).IPv4Prot)
							{
								case 0x06: L4Protocol = Protocols.TCP; break;
								case 0x11: L4Protocol = Protocols.UDP; break;
								default: DoneParsing = true; break;
							}
						break;
					case Protocols.IPv6:
					default:
						break;
				}

			Data = new byte[RemainingLength];
			fs.Read(Data, 0, (int)RemainingLength);
		}

	}
	public class PktCrit : INotifyPropertyChanged
	{
		private uint CritType;    // 0 = empty, i.e., all packets will match
		// 1 = dest mac
		// 2 = src mac
		// 3 = ether type/len field
		// 4 = src ip
		// 5 = dest ip
		// -1 = general
		private ulong mask;
		private uint reln;    // 0 = equals, 1 = not equals
		private ulong comparevalue;
		public event PropertyChangedEventHandler PropertyChanged;

		protected void Notify()
		{
			if (this.PropertyChanged != null)
				PropertyChanged(this, new PropertyChangedEventArgs(null));
		}
		public PktCrit(uint type, ulong msk, uint rel, ulong val)
		{
			CritType = type; mask = msk; reln = rel; comparevalue = val;
			Notify();
		}
		private bool Compare(ulong val)
		{
			if (reln == 0) return (val & mask) == comparevalue;
			else return (val & mask) != comparevalue;
		}
		public bool PktCompare(PcapPkt pkt)
		{
			switch (CritType)
			{
				case 0: return true;
				case 1: return Compare(((EthernetHeader)(pkt.L2Hdr)).DestMAC);
				case 2: return Compare(((EthernetHeader)(pkt.L2Hdr)).SrcMAC);
				case 3: return Compare(((EthernetHeader)(pkt.L2Hdr)).TypeLen);
				case 4: return true;
				case 5: return true;
				default: return false;
			}
		}
		public string CritInfo { get { return string.Format("type {0} mask {1:x8} reln {2} comparevalue {3:x4}", CritType, mask, reln, comparevalue); } }
	}
	public class PktSet : INotifyPropertyChanged
	{
		private string name;
		public ObservableCollection<PktCrit> criteria { get; set; }
		public ObservableCollection<PcapPkt> pkts { get; set; }

		public event PropertyChangedEventHandler PropertyChanged;

		protected void Notify()
		{
			if (this.PropertyChanged != null)
				PropertyChanged(this, new PropertyChangedEventArgs(null));
		}

		public PktSet(string n)     // add new packet set with default criteria
		{
			name = n;
			criteria = new ObservableCollection<PktCrit>();
			pkts = new ObservableCollection<PcapPkt>();
			criteria.Add(new PktCrit(0, 0, 0, 0));      // criteria list must always contain at least one
		}
		public PktSet(string n, PktCrit crit)     // add new packet set at beginning of list with specified criteria
		{
			name = n;
			criteria = new ObservableCollection<PktCrit>();
			pkts = new ObservableCollection<PcapPkt>();
			criteria.Add(crit);
		}
		public bool PktSetConsiderPkt(PcapPkt pkt)
		{    // tests a packet against criteria for this set, adds it if match, returns true if added, false if not
			foreach (PktCrit crit in criteria)
			{
				if (crit.PktCompare(pkt))
				{
					pkts.Add(pkt);
					Notify();
					return true;
				}
			}
			return false;
		}

		public string Info
		{
			get { return name + ", count=" + pkts.Count; }
		}
	}
	public class PktSetList : INotifyPropertyChanged
	{
		public ObservableCollection<PktSet> sets { get; set; }

		public event PropertyChangedEventHandler PropertyChanged;

		protected void Notify()
		{
			if (this.PropertyChanged != null)
				PropertyChanged(this, new PropertyChangedEventArgs(null));
		}

		public PktSetList()
		{
			sets = new ObservableCollection<PktSet>();
			sets.Add(new PktSet("default packet set"));     // packet set list must always include at least one set
			Notify();                                       // this creates one set with the default criteria, which matches all packets
		}

		public int PktSetListAdd(PcapPkt pkt)       // adds a packet to the set list, returns 0 if added to a set, -1 if not added to any set (which should never happen)
		{
			foreach (PktSet set in this.sets)
			{
				if (set.PktSetConsiderPkt(pkt)) return 0;
			}
			return -1;                              // return -1 if packet did not meet criteria in any set
		}
	}









	public partial class MainWindow : Window
	{
		public PcapFileHdr pfh;
		public PktSetList setlist = new PktSetList();
		public QuickFilter QF = new QuickFilter();

		string s;
		public Dictionary<string, HeaderField> HF = new Dictionary<string, HeaderField>();
		public static DataGrid PacketDG;    // copy of packet data grid reference, static so that other classes can refer to it
		public static Dictionary<Protocols, Dictionary<string, HeaderField>> HFDict = new Dictionary<Protocols, Dictionary<string, HeaderField>>();
		// master dictionary of header field information
		// top level is dict by protocol
		// each entry is in turn a dictionary of HeaderField by field name
		public MainWindow()
		{
			InitializeComponent();
			grid.DataContext = setlist.sets;
			PacketDG = PacketDataGrid;

			//setlist.sets.Insert(0,new PktSet("ARP packets", new PktCrit(3,0xffffffff, 0, 0x0806)));
		}

		private void ChooseFile(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			Nullable<bool> result;
			FileStream fs;
			PktSet p = setlist.sets[0];

			dlg.Multiselect = false;
			dlg.InitialDirectory = "C:\\capfiles\\";
			result = dlg.ShowDialog();

			if (result == true)
			{
				filename.Content = dlg.FileName;
				fs = new FileStream(dlg.FileName, FileMode.Open);
				pfh = new PcapFileHdr(fs);
				while (fs.Position < fs.Length) setlist.PktSetListAdd(new PcapPkt(fs, pfh));
				fs.Close();
			}
			else MessageBox.Show("No file chosen, so no action taken");
		}

		// BUTTON CLICK HANDLER TO TOGGLE VISIBILITY OF TWO ELEMENTS IN SAME GRID SLOT
		/*private void DGBClick(object sender, RoutedEventArgs e)
		{
			if (DG1.Visibility == Visibility.Visible) { DG1.Visibility = Visibility.Hidden; DG2.Visibility = Visibility.Visible; }
			else { DG2.Visibility = Visibility.Hidden; DG1.Visibility = Visibility.Visible; }
		}*/
		private void qf(object sender, RoutedEventArgs e)
		{
			Window qf = new QuickFilterDialog(QF);
			qf.ShowDialog();
		}
		private void showethertoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showetherfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
			foreach (HeaderField h in HFDict[Protocols.Ethernet].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showarpbasictoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showarpbasicfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
			foreach (HeaderField h in HFDict[Protocols.ARP].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showarpdetailtoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showarpdetailfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
			foreach (HeaderField h in HFDict[Protocols.ARP].Values) if (!h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showipv4basictoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showipv4basicfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
			foreach (HeaderField h in HFDict[Protocols.IPv4].Values) if (h.Basic) h.DGCol.Visibility = newvis;
		}
		private void showipv4detailtoggle(object sender, RoutedEventArgs e)
		{
			Visibility newvis = (bool)showipv4detailfields.IsChecked ? Visibility.Visible : Visibility.Hidden;
			foreach (HeaderField h in HFDict[Protocols.IPv4].Values) if (!h.Basic) h.DGCol.Visibility = newvis;
		}

	}
}
