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
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;


namespace pviewer5
{

    // next:
    //      redo tdgitem to use IP4g, GTypeg and Protocolsg
    //      redo axes and window code to use the above
    //      implement grouping buckets and logic described in spreadsheet






    /*  old tdgitem spec
     *  public class tdgitem : INotifyPropertyChanged
        {
            public string timestamp { get; set; }
            public IP4 ip { get; set; }
            public Protocols proto { get; set; }
            public object group { get; set; }
            public Type grouptype { get { return group.GetType(); } }
            public ObservableCollection<tdgitem> parent { get; set; }

            public string grouped_ip { get; set; }
            public string grouped_proto { get; set; }
            public object grouped_group { get; set; }
            public Type grouped_grouptype { get; set; }

            public tdgitem(string t, string i, string p, object g, ObservableCollection<tdgitem> par)
            {
                timestamp = t;
                ip = i;
                proto = p;
                group = g;
                parent = par;
                switch (ip)
                {
                    case "192.168.11.222":
                        grouped_ip = "OTHER";
                        break;
                    case "192.168.11.224":
                        grouped_ip = "OTHER";
                        break;
                    default:
                        grouped_ip = ip;
                        break;
                }
                grouped_proto = proto;
                grouped_group = group;
                grouped_grouptype = grouptype;
            }

            // implement INotifyPropertyChanged
            public event PropertyChangedEventHandler PropertyChanged;
            private void NotifyPropertyChanged(String propertyName = "")
            {
                if (PropertyChanged != null)
                {
                    PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
                }
            }


        }
        */


    public class tdggroupingaxis : INotifyPropertyChanged
    {
        public string propertyname { get; set; }
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public ObservableCollection<tdggroupingaxis> parent;

        public tdggroupingaxis(string pn, string dn, ObservableCollection<tdggroupingaxis> par)
        {
            propertyname = pn;
            displayname = dn;
            ischecked = true;
            parent = par;
        }


        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

    }




    public partial class TestDataGrid : Window
    {
        public ObservableCollection<Packet> vl { get; set; }
        public ListCollectionView view;

        public ObservableCollection<tdggroupingaxis> axes { get; set; }

        public static RoutedCommand tdg_break_out_cmd = new RoutedCommand();
        public static RoutedCommand tdg_group_cmd     = new RoutedCommand();

        CommandBinding tdg_break_out_binding;
        CommandBinding tdg_group_binding;

        public string arpgroup1 = "arpgroup1";
        public string arpgroup2 = "arpgroup2";
        public int httpgroup1 = 1;
        public int httpgroup2 = 2;

        public TestDataGrid()
        {
            vl = new ObservableCollection<Packet>();
            axes = new ObservableCollection<tdggroupingaxis>();

            InitializeComponent();
            tdggrid.DataContext = this;

            tdg_break_out_binding = new CommandBinding(tdg_break_out_cmd, tdg_break_out_Executed, tdg_break_out_CanExecute);
            tdg_group_binding     = new CommandBinding(tdg_group_cmd,     tdg_group_Executed,     tdg_group_CanExecute);
            tdg.CommandBindings.Add(tdg_break_out_binding);
            tdg.CommandBindings.Add(tdg_group_binding);


            vl.Add(new Packet()); vl[00].ip4g = new IP4g(0xc0a80b03); vl[00].protocolsg = new Protocolsg(Protocols.ARP); vl[00].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[01].ip4g = new IP4g(0xc0a80b04); vl[01].protocolsg = new Protocolsg(Protocols.ARP); vl[01].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[02].ip4g = new IP4g(0xc0a80b02); vl[02].protocolsg = new Protocolsg(Protocols.DNS); vl[02].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[03].ip4g = new IP4g(0xc0a80b03); vl[03].protocolsg = new Protocolsg(Protocols.TCP); vl[03].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[04].ip4g = new IP4g(0xc0a80b02); vl[04].protocolsg = new Protocolsg(Protocols.TCP); vl[04].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[05].ip4g = new IP4g(0xc0a80b02); vl[05].protocolsg = new Protocolsg(Protocols.TCP); vl[05].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[06].ip4g = new IP4g(0xc0a80b04); vl[06].protocolsg = new Protocolsg(Protocols.ARP); vl[06].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[07].ip4g = new IP4g(0xc0a80b02); vl[07].protocolsg = new Protocolsg(Protocols.TCP); vl[07].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[08].ip4g = new IP4g(0xc0a80b03); vl[08].protocolsg = new Protocolsg(Protocols.ARP); vl[08].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[09].ip4g = new IP4g(0xc0a80b03); vl[09].protocolsg = new Protocolsg(Protocols.ARP); vl[09].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[10].ip4g = new IP4g(0xc0a80b05); vl[10].protocolsg = new Protocolsg(Protocols.ARP); vl[10].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[11].ip4g = new IP4g(0xc0a80b06); vl[11].protocolsg = new Protocolsg(Protocols.ARP); vl[11].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[12].ip4g = new IP4g(0xc0a80b02); vl[12].protocolsg = new Protocolsg(Protocols.ARP); vl[12].gtypeg = new GTypeg(typeof(ARPG));
            vl.Add(new Packet()); vl[13].ip4g = new IP4g(0xc0a80b02); vl[13].protocolsg = new Protocolsg(Protocols.TCP); vl[13].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[14].ip4g = new IP4g(0xc0a80b02); vl[14].protocolsg = new Protocolsg(Protocols.TCP); vl[14].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[15].ip4g = new IP4g(0xc0a80b02); vl[15].protocolsg = new Protocolsg(Protocols.TCP); vl[15].gtypeg = new GTypeg(typeof(HTTPG));
            vl.Add(new Packet()); vl[16].ip4g = new IP4g(0xc0a80b02); vl[16].protocolsg = new Protocolsg(Protocols.TCP); vl[16].gtypeg = new GTypeg(typeof(HTTPG));

/*            vl.Add(new tdgitem("002", "192.168.11.223", "arp", arpgroup1,  vl));
            vl.Add(new tdgitem("003", "192.168.11.224", "arp", arpgroup1,  vl));
            vl.Add(new tdgitem("004", "192.168.11.222", "dns", httpgroup1, vl));
            vl.Add(new tdgitem("005", "192.168.11.223", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("006", "192.168.11.222", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("007", "192.168.11.222", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("008", "192.168.11.224", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("009", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("010", "192.168.11.223", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("011", "192.168.11.223", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("012", "192.168.11.225", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("013", "192.168.11.226", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("014", "192.168.11.222", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("015", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("016", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("017", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("018", "192.168.11.222", "tcp", httpgroup2, vl));
*/
            axes.Add(new tdggroupingaxis("grouped_proto", "Protocol", axes));
            axes.Add(new tdggroupingaxis("grouped_ip", "IP Address", axes));
            axes.Add(new tdggroupingaxis("grouped_group", "Group", axes));


            // next line gets view on vl, not on tdg.Itemssource
            // at this point in execution, tdg.Itemssource is still null,
            // even though it must get set somewhere later on because the datagrid
            // does get populated correctly
            view = (ListCollectionView)CollectionViewSource.GetDefaultView(vl);
            
            SetGrouping();

        }

        void SetGrouping()
        {
            view.GroupDescriptions.Clear();
            foreach (tdggroupingaxis a in axes)
                if (a.ischecked)
                    view.GroupDescriptions.Add(new PropertyGroupDescription(a.propertyname));
        }

        void tdgaxischeck_Click(object sender, RoutedEventArgs e)
        {
            CheckBox b = (CheckBox)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            SetGrouping();
        }

        void tdgaxisbutton_Click(object sender, RoutedEventArgs e)
        {
            Button b = (Button)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            ObservableCollection<tdggroupingaxis> mylist = i.parent;
            int pos = mylist.IndexOf(i);

            switch (b.Name)
            {
                case "button_top":
                    mylist.Move(pos, 0); break;
                case "button_up":
                    if (pos == 0) break;
                    mylist.Move(pos, pos - 1); break;
                case "button_dn":
                    if (pos == mylist.Count() - 1) break;
                    mylist.Move(pos, pos + 1); break;
                case "button_bot":
                    mylist.Move(pos, mylist.Count() - 1); break;
                default: break;
            }

            SetGrouping();

        }

        public void tdg_break_out_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            tdgitem t = (tdgitem)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
                // change grouped_xx to specific value
                // do this for all packets that have this specific value - need to pass through entire packet list

            switch(column)
            {
                case "ip":
                    if (t.grouped_ip == "OTHER")
                    {
                        foreach (tdgitem i in vl)
                            if (i.ip == t.ip) i.grouped_ip = i.ip;
                        view.Refresh();
                    }
                    break;
                default:
                    break;
            }

            
        }
        public void tdg_break_out_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            tdgitem t = (tdgitem)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
            // change grouped_xx to specific value
            // do this for all packets that have this specific value - need to pass through entire packet list

            switch (column)
            {
                case "ip":
                    e.CanExecute = (t.grouped_ip == "OTHER");
                    break;
                default:
                    e.CanExecute = false;
                    break;
            }
        }

        public void tdg_group_Executed(object sender, ExecutedRoutedEventArgs e)
        {
            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            tdgitem t = (tdgitem)(dg.CurrentCell.Item);

            switch (column)
            {
                case "ip":
                    if (t.grouped_ip != "OTHER")
                    {
                        foreach (tdgitem i in vl)
                            if (i.ip == t.ip) i.grouped_ip = "OTHER";
                        view.Refresh();
                    }
                    break;
                default:
                    break;
            }

        }
        public void tdg_group_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            tdgitem t = (tdgitem)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
            // change grouped_xx to specific value
            // do this for all packets that have this specific value - need to pass through entire packet list

            switch (column)
            {
                case "ip":
                    e.CanExecute = (t.grouped_ip != "OTHER");
                    break;
                default:
                    e.CanExecute = false;
                    break;
            }
        }

    }


}
