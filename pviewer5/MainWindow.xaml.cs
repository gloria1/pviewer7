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
        ARP =0x80,
        IP6 = 0x100,
        TCP = 0x200,
        UDP = 0x400,
        ICMP =0x800,
        IGMP =0x1000,
        GGP =0x2000,
        DHCP4 =0x4000,
        BOOTP =0x8000,
        DNS =0x10000
    }



    public class Packet
    {
        public Protocols Prots;     // flags for protocols present in this packet
        public List<H> phlist { get; set; }
        public ulong DataLen;

        // convenience fields to contain copies of commonly needed values,
        // so that other functions do not need to search through header list to find them
        public H groupprotoheader { get; set; }     // packet group logic will set this to point to the header of the protocol relevant to that group type
        public ulong SrcMAC = 0;
        public ulong DestMAC = 0;
        public uint SrcIP4 = 0;
        public uint DestIP4 = 0;
        public uint SrcPort = 0;       // UPD or TCP port, if any
        public uint DestPort = 0;

        public string packetdisplayinfo { get { return "Packet innermost header: " + phlist[phlist.Count - 1].headerdisplayinfo; } }

        public byte[] Data;
        public bool qfexcluded;		// true if packet was excluded due to quickfilter - can drop once we transition to simply deleting quickfilter'ed packets

        public Packet(FileStream fs, PcapFile pfh)
        {
            PcapH pch;
            Prots = 0;
            phlist = new List<H>();

            DataLen = (ulong)(fs.Length - fs.Position);    // need to parse headers to determine lengths of data array for packet

            // instantiate pcap header - that constructor will start cascade of constructors for inner headers
            pch = new PcapH(fs, pfh, this, ref DataLen);    // header constuctors will reduce DataLen for the bytes they consume, so that when this returns, DataLen will be only the bytes from the packet that have not been processed into the header list

            Data = new byte[DataLen];
            fs.Read(Data, 0, (int)DataLen);

            if (pfh.Type == PcapFile.PcapFileTypes.PcapNG)
                fs.Seek((long)(pch.NGBlockLen - 0x1c - pch.CapLen), SeekOrigin.Current);       // skip over any padding bytes, options and trailing block length field
        }
    }


    public class PcapFileUtil       // class for functions for working with pcap and pcapng files
    {
        public static string LastDirectory = "C:\\users\\csadmin\\skydrive\\capfiles\\";
        public static string LastFile = "";

        public PcapFileUtil()      // constructor - not used for anything
        { }
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

        public ObservableCollection<Packet> pkts { get; set; }
        public ObservableCollection<Packet> exclpkts { get; set; }
        public ObservableCollection<GList> grouplistlist { get; set; }
        
    //    public static DataGrid PacketDG;    // copy of packet data grid reference, static so that other classes can refer to it
	// TEMPORARY - PROVISION FOR VIEWING QF EXLUDED PACKETS
		// WHEN NO LONGER NEEDED, ALSO DELETE
		//		CODE IN ETHER AND IP4 HEADER STATIC CONSTRUCTORS THAT CREATES THE EXTRA HF ENTRIES
		//public static DataGrid ExclDG;    // copy of packet data grid reference, static so that other classes can refer to it
		
		public static DisplaySettings ds = new DisplaySettings();

		public MainWindow()
		{
            pkts = new ObservableCollection<Packet>();
            exclpkts = new ObservableCollection<Packet>();

            grouplistlist = new ObservableCollection<GList>();
            grouplistlist.Add(new DNSGList("DNS Groups"));
            grouplistlist.Add(new DHCP4GList("DHCP4 Groups"));
            grouplistlist.Add(new TCPGList("TCP Groups"));
            grouplistlist.Add(new UDPGList("UDP Groups"));
            grouplistlist.Add(new ARPGList("ARP Groups"));
            grouplistlist.Add(new GList("Ungrouped Packets"));

            InitializeComponent();

			grid.DataContext = this;
			//QFExclGrid.DataContext = qfexcluded;
			//PacketDG = PacketDataGrid;
			//ExclDG = QFExclGrid;

		}

		private void ChooseFile(object sender, RoutedEventArgs e)
		{
			PcapFile pfh;
			OpenFileDialog dlg = new OpenFileDialog();
			Nullable<bool> result;
			FileStream fs;
			Packet pkt;

            byte[] b = new byte[1000];

			dlg.Multiselect = false;
			dlg.InitialDirectory = PcapFileUtil.LastDirectory;
            dlg.FileName = PcapFileUtil.LastFile;
			result = dlg.ShowDialog();

			if (result == true)
			{
                pkts.Clear();
                exclpkts.Clear();
                foreach (GList gl in grouplistlist) gl.groups.Clear();

				QuickFilterTools.QFMAC.ResetCounters();
				QuickFilterTools.QFIP4.ResetCounters();
				//foreach (PktSet set in setlist.sets) set.pkts.Clear();
				//qfexcluded.pkts.Clear();
				filename.Content = dlg.FileName;
				fs = new FileStream(dlg.FileName, FileMode.Open);

                pfh = new PcapFile(fs);

                while (fs.Position < fs.Length)
                {
                    pkt = new Packet(fs, pfh);
                    // NEXT LINE IS TEMPORARY - ONCE QUICKFILTER IS TRUSTED, PACKETS THAT ARE EXCLUDED SHOULD SIMPLY BE DESTROYED
                    if (pkt.qfexcluded) exclpkts.Add(pkt);
                    else pkts.Add(pkt);
                }

                foreach (Packet p in pkts)
                    foreach (GList gl in grouplistlist)
                        if (gl.GroupPacket(p)) break;

                foreach (TCPG tg in ((TCPGList)(grouplistlist[2])).groups)
                {
                    tg.OPL1.CopyBytes(1000, b);
                    tg.OPL2.CopyBytes(1000, b);
                }
                CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();

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
			CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();
			CollectionViewSource.GetDefaultView(QFExclGrid.ItemsSource).Refresh();
		}
		private void inmbutton(object sender, RoutedEventArgs e)
		{
			Window w1 = new IP4NameMapDialog();
			w1.ShowDialog();
			CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();
            CollectionViewSource.GetDefaultView(QFExclGrid.ItemsSource).Refresh();
		}
		private void displayaliastoggle(object sender, RoutedEventArgs e)
		{
			ds.DisplayAliases = (bool)displayaliascheckbox.IsChecked;
			CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();
            CollectionViewSource.GetDefaultView(QFExclGrid.ItemsSource).Refresh();
		}
		private void displayIP4inhextoggle(object sender, RoutedEventArgs e)
		{
			ds.DisplayIP4InHex = (bool)displayIP4inhexcheckbox.IsChecked;
			CollectionViewSource.GetDefaultView(grouptree.ItemsSource).Refresh();
            CollectionViewSource.GetDefaultView(QFExclGrid.ItemsSource).Refresh();
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
			//ulong q;

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
