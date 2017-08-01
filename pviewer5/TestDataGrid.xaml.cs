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
    

    public class tdggroupingaxis : INotifyPropertyChanged
    {
        public string propertyname { get; set; }    // name of the property in Packet that this axis relates to
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public ObservableCollection<tdggroupingaxis> parent;
        public List<Object> ungrouped_items;

        public static tdggroupingaxis IP4axis;
        public static tdggroupingaxis Protocolaxis;
        public static tdggroupingaxis GTypeaxis;

        public tdggroupingaxis(string pn, string dn, ObservableCollection<tdggroupingaxis> par)
        {
            propertyname = pn;
            displayname = dn;
            ischecked = true;
            parent = par;
            ungrouped_items = new List<object>();
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


            vl.Add(new Packet()); vl[00].ip4temp = 0xc0a80b04; vl[00].prottemp = Protocols.ARP; vl[00].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[01].ip4temp = 0xc0a80b04; vl[01].prottemp = Protocols.ARP; vl[01].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[02].ip4temp = 0xc0a80b02; vl[02].prottemp = Protocols.DNS; vl[02].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[03].ip4temp = 0xc0a80b03; vl[03].prottemp = Protocols.TCP; vl[03].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[04].ip4temp = 0xc0a80b02; vl[04].prottemp = Protocols.TCP; vl[04].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[05].ip4temp = 0xc0a80b02; vl[05].prottemp = Protocols.TCP; vl[05].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[06].ip4temp = 0xc0a80b04; vl[06].prottemp = Protocols.ARP; vl[06].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[07].ip4temp = 0xc0a80b02; vl[07].prottemp = Protocols.TCP; vl[07].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[08].ip4temp = 0xc0a80b03; vl[08].prottemp = Protocols.ARP; vl[08].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[09].ip4temp = 0xc0a80b03; vl[09].prottemp = Protocols.ARP; vl[09].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[10].ip4temp = 0xc0a80b05; vl[10].prottemp = Protocols.ARP; vl[10].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[11].ip4temp = 0xc0a80b06; vl[11].prottemp = Protocols.ARP; vl[11].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[12].ip4temp = 0xc0a80b02; vl[12].prottemp = Protocols.ARP; vl[12].gtypetemp = GTypes.ARP;
            vl.Add(new Packet()); vl[13].ip4temp = 0xc0a80b02; vl[13].prottemp = Protocols.TCP; vl[13].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[14].ip4temp = 0xc0a80b02; vl[14].prottemp = Protocols.TCP; vl[14].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[15].ip4temp = 0xc0a80b02; vl[15].prottemp = Protocols.TCP; vl[15].gtypetemp = GTypes.HTTP;
            vl.Add(new Packet()); vl[16].ip4temp = 0xc0a80b02; vl[16].prottemp = Protocols.TCP; vl[16].gtypetemp = GTypes.HTTP;

            tdggroupingaxis.Protocolaxis = new tdggroupingaxis("protocolsg", "Protocol", axes); axes.Add(tdggroupingaxis.Protocolaxis);
            tdggroupingaxis.IP4axis =  new tdggroupingaxis("ip4g", "IP Address", axes); axes.Add(tdggroupingaxis.IP4axis);
            tdggroupingaxis.GTypeaxis = new tdggroupingaxis("gtypeg", "Group Type", axes); axes.Add(tdggroupingaxis.GTypeaxis);


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
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
                // change grouped_xx to specific value
                // do this for all packets that have this specific value - need to pass through entire packet list

            switch(column)
            {
                case "ip":
                    if (p.ip4g.grouped)
                    {
                        foreach (Packet i in vl)
                            if (i.ip4g == p.ip4g) i.ip4g.grouped = false;
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
                case "ip":
                    e.CanExecute = (p.ip4g.grouped);
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
                case "ip":
                    if (!p.ip4g.grouped)
                    {
                        foreach (Packet i in vl)
                            if (i.ip4g.ip4 == p.ip4g.ip4) i.ip4g.grouped = true;
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
                case "ip":
                    e.CanExecute = (!p.ip4g.grouped);
                    break;
                default:
                    e.CanExecute = false;
                    break;
            }
        }

    }


}
