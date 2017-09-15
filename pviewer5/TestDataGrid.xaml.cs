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

            vl.Add(new Packet()); vl[00].ip4g = vl[00].SrcIP4 = 0xc0a80b03; vl[00].protocolsg = vl[00].Prots = Protocols.ARP; vl[00].gtypeg = vl[00].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[01].ip4g = vl[01].SrcIP4 = 0xc0a80b04; vl[01].protocolsg = vl[01].Prots = Protocols.ARP; vl[01].gtypeg = vl[01].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[02].ip4g = vl[02].SrcIP4 = 0xc0a80b02; vl[02].protocolsg = vl[02].Prots = Protocols.DNS; vl[02].gtypeg = vl[02].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[03].ip4g = vl[03].SrcIP4 = 0xc0a80b03; vl[03].protocolsg = vl[03].Prots = Protocols.TCP; vl[03].gtypeg = vl[03].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[04].ip4g = vl[04].SrcIP4 = 0xc0a80b02; vl[04].protocolsg = vl[04].Prots = Protocols.TCP; vl[04].gtypeg = vl[04].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[05].ip4g = vl[05].SrcIP4 = 0xc0a80b02; vl[05].protocolsg = vl[05].Prots = Protocols.TCP; vl[05].gtypeg = vl[05].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[06].ip4g = vl[06].SrcIP4 = 0xc0a80b04; vl[06].protocolsg = vl[06].Prots = Protocols.ARP; vl[06].gtypeg = vl[06].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[07].ip4g = vl[07].SrcIP4 = 0xc0a80b02; vl[07].protocolsg = vl[07].Prots = Protocols.TCP; vl[07].gtypeg = vl[07].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[08].ip4g = vl[08].SrcIP4 = 0xc0a80b03; vl[08].protocolsg = vl[08].Prots = Protocols.ARP; vl[08].gtypeg = vl[08].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[09].ip4g = vl[09].SrcIP4 = 0xc0a80b03; vl[09].protocolsg = vl[09].Prots = Protocols.ARP; vl[09].gtypeg = vl[09].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[10].ip4g = vl[10].SrcIP4 = 0xc0a80b05; vl[10].protocolsg = vl[10].Prots = Protocols.ARP; vl[10].gtypeg = vl[10].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[11].ip4g = vl[11].SrcIP4 = 0xc0a80b06; vl[11].protocolsg = vl[11].Prots = Protocols.ARP; vl[11].gtypeg = vl[11].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[12].ip4g = vl[12].SrcIP4 = 0xc0a80b02; vl[12].protocolsg = vl[12].Prots = Protocols.ARP; vl[12].gtypeg = vl[12].gtypegtemp = typeof(ARPG);
            vl.Add(new Packet()); vl[13].ip4g = vl[13].SrcIP4 = 0xc0a80b02; vl[13].protocolsg = vl[13].Prots = Protocols.TCP; vl[13].gtypeg = vl[13].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[14].ip4g = vl[14].SrcIP4 = 0xc0a80b02; vl[14].protocolsg = vl[14].Prots = Protocols.TCP; vl[14].gtypeg = vl[14].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[15].ip4g = vl[15].SrcIP4 = 0xc0a80b02; vl[15].protocolsg = vl[15].Prots = Protocols.TCP; vl[15].gtypeg = vl[15].gtypegtemp = typeof(HTTPG);
            vl.Add(new Packet()); vl[16].ip4g = vl[16].SrcIP4 = 0xc0a80b02; vl[16].protocolsg = vl[16].Prots = Protocols.TCP; vl[16].gtypeg = vl[16].gtypegtemp = typeof(HTTPG);
            
            axes.Add(new tdggroupingaxis("protocolsg", "Protocol", axes));
            axes.Add(new tdggroupingaxis("ip4g", "IP Address", axes));
            axes.Add(new tdggroupingaxis("gtypeg", "Group", axes));


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

            view.Refresh();

            // Traverse(null, tdg);

        }

        void Traverse(DependencyObject parent, DependencyObject depo)
        {
            DependencyObject child;
            int ccount = VisualTreeHelper.GetChildrenCount(depo);

            for (int i = 0; i < ccount; i++)
            {
                child = VisualTreeHelper.GetChild(depo, i);
                if (parent != null)
                {
                    if ((typeof(System.Windows.Controls.Grid) == depo.GetType()) && (typeof(System.Windows.Controls.ScrollContentPresenter) != child.GetType()))
                        continue;
                }
                Traverse(depo, child);
            }
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
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
                // change grouped_xx to specific value
                // do this for all packets that have this specific value - need to pass through entire packet list

            switch(column)
            {
                case "ip4g":
                    if (p.ip4g == null)
                    {
                        foreach (Packet i in vl)
                            if (i.SrcIP4 == p.SrcIP4) i.ip4g = i.SrcIP4;
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
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
            // change grouped_xx to specific value
            // do this for all packets that have this specific value - need to pass through entire packet list

            switch (column)
            {
                case "SrcIP4":
                    e.CanExecute = (p.ip4g == null);
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
            Packet p = (Packet)(dg.CurrentCell.Item);

            switch (column)
            {
                case "SrcIP4":
                    if (p.ip4g != null)
                    {
                        foreach (Packet i in vl)
                            if (i.SrcIP4 == p.SrcIP4) i.ip4g = null;
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
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
            // change grouped_xx to specific value
            // do this for all packets that have this specific value - need to pass through entire packet list

            switch (column)
            {
                case "SrcIP4":
                    e.CanExecute = (p.ip4g != null);
                    break;
                default:
                    e.CanExecute = false;
                    break;
            }
        }

    }


}
