using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
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
using System.Collections;
using System.Reflection;

namespace pviewer5
{

    /*
     * PRIOR tdggroupingaxis classes

    public class tdggroupingaxis : INotifyPropertyChanged
    {
        public string propertyname { get; set; }
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public List<tdggroupingaxis> parent { get; set; }

        public List<object> groupeditems = new List<object>();
        public Func<Packet, bool> isgrouped      ;   // will be a function to determine whether the packet is grouped for its value on this axis
        
        public tdggroupingaxis(List<tdggroupingaxis> par)
        {
            ischecked = true;
            parent = par;
        }

        public virtual List<List<Packet>> groupfn(List<Packet> pkts)
        {
            return null;
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

    public class tdggroupingaxisip4 : tdggroupingaxis
    {
        public tdggroupingaxisip4(List<tdggroupingaxis> par) : base(par)
        {
            propertyname = "SrcIP4";
            displayname = "Source IP4";
        }

        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, IP4?>(x => x.IP4g));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
    }

    public class tdggroupingaxisprot : tdggroupingaxis
    {
        public tdggroupingaxisprot(List<tdggroupingaxis> par) : base(par)
        {
            propertyname = "ProtOuter";
            displayname = "Protocol";
        }
        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, Protocols?>(x => x.Protocolsg));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
    }

    public class tdggroupingaxispgtype : tdggroupingaxis
    {
        public tdggroupingaxispgtype(List<tdggroupingaxis> par) : base(par)
        {
            propertyname = "PGType";
            displayname = "Packet Group Type";
        }
        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, Type>(x => x.PGTypeg));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
    }



    public class tdgtreegroup : PVDisplayObject
    {
        public tdggroupingaxis axis { get; set; }

        public tdgtreegroup(tdggroupingaxis ax, PVDisplayObject par) : base (par)
        {
            axis = ax;
            L = new ObservableCollection<PVDisplayObject>();
        }
    }

    */



    public class tdggroupingaxis : INotifyPropertyChanged
    {
        public Type type { get; set; }
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public List<tdggroupingaxis> parent { get; set; }

        public tdggroupingaxis(List<tdggroupingaxis> par)
        {
            type = typeof(object);
            ischecked = true;
            parent = par;
        }

        public virtual List<List<Packet>> groupfn(List<Packet> pkts)
        {
            return null;
        }
        public virtual object getkey(Packet p)
        {
            return null;
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

    public class tdggroupingaxisprot : tdggroupingaxis
    {
        public tdggroupingaxisprot(List<tdggroupingaxis> par) : base(par)
        {
            type = typeof(Protocols?);
            displayname = "Protocols";
        }
        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, Protocols?>(x => x.Protocolsg));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
        public override object getkey(Packet p)
        {
            return p.Protocolsg;
        }
    }

    public class tdggroupingaxisip4 : tdggroupingaxis
    {
        public tdggroupingaxisip4(List<tdggroupingaxis> par) : base(par)
        {
            type = typeof(IP4?);
            displayname = "IP4 address";
        }
        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, IP4?>(x => x.IP4g));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
        public override object getkey(Packet p)
        {
            return p.IP4g;
        }
    }

    public class tdggroupingaxispgtype : tdggroupingaxis
    {
        public tdggroupingaxispgtype(List<tdggroupingaxis> par) : base(par)
        {
            type = typeof(Type);
            displayname = "Packet Group Type";
        }

        public override List<List<Packet>> groupfn(List<Packet> pkts)
        {
            List<List<Packet>> result = new List<List<Packet>>();
            var query = (pkts.GroupBy<Packet, Type>(x => x.PGTypeg));
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
        public override object getkey(Packet p)
        {
            return p.PGTypeg;
        }
    }


    public class tdgnode : PVDisplayObject
    {
        public Type keytype { get; set; }  // the type of the key - we cannot just use key.GetType because the key may be null
        public object key { get; set; }   // the common value of the key for the axis of this level of the tree for the items in this node

        public tdgnode(Type t, object k, PVDisplayObject par) : base(par)
        {
            keytype = t;
            key = k;
            // note: L will be instantiated by the tree building function, based on the type of the objects under this node
        }
        public override string displayinfo
        {
            get
            {
                if (keytype == null) return "Unknown";
                else if (keytype == typeof(IP4?)) return "IP4 address = " + ((key == null) ? "All Other" : ((IP4?)key).ToString());
                else if (keytype == typeof(Protocols?)) return "Protocol = " + ((key == null) ? "All Other" : ((Protocols?)key).ToString());
                else if (keytype == typeof(Type)) return "Packet Group Type = " + ((key == null) ? "All Other" : ((Type)key).ToString());
                else return "Unknown";
            }
        }
    }

    public class pktlist : ObservableCollection<PVDisplayObject> { }

  //  WHY DOESN'T pktlist TRIGGER THE pktlist DATA TEMPLATE????

    public class tdgleaf : tdgnode
    {
        public tdgleaf(Type t, object k, PVDisplayObject par) : base(t, k, par)
        {
        }

/*        private ObservableCollection<Packet> _L = null;
        public ObservableCollection<Packet> L
        {
            get { return _L; }
            set
            {
                _L = value;
                NotifyPropertyChanged();
                if (value != null)
                {
                    Lview = (ListCollectionView)CollectionViewSource.GetDefaultView(value);
                    Lview.Filter = new Predicate<object>(PVDOFilter);
                }
            }
        }
        */

    }


    public partial class TestDataGrid : Window
    {
        public tdgnode root;
        public List<tdggroupingaxis> axes { get; set; } = new List<tdggroupingaxis>();
        public List<Packet> pkts = new List<Packet>();


        public static RoutedCommand tdg_break_out_cmd = new RoutedCommand();
        public static RoutedCommand tdg_group_cmd     = new RoutedCommand();

        CommandBinding tdg_break_out_binding;
        CommandBinding tdg_group_binding;

         public TestDataGrid()
        {
            Packet p;

            InitializeComponent();
            tdggrid.DataContext = this;

            tdg_break_out_binding = new CommandBinding(tdg_break_out_cmd, tdg_break_out_Executed, tdg_break_out_CanExecute);
            tdg_group_binding     = new CommandBinding(tdg_group_cmd,     tdg_group_Executed,     tdg_group_CanExecute);
            tdgtree.CommandBindings.Add(tdg_break_out_binding);
            tdgtree.CommandBindings.Add(tdg_group_binding);

            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b04; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.DNS; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b04; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b05; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b06; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.Prots = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);

            axes.Add(new tdggroupingaxisprot(axes));
            axes.Add(new tdggroupingaxispgtype(axes));
            axes.Add(new tdggroupingaxisip4(axes));


            BuildTreeNode(out root, null, null, pkts, axes, 0, null);
     

        }

        void BuildTreeNode(out tdgnode t, Type type, object key, List<Packet> pkts, List<tdggroupingaxis> axes, int axisnum, tdgnode parent)    // builds out next level of tree under t, based on axes[axisnum]
        {
            int subaxes;
            tdgnode tnew;

            // find next active axis in axes starting at axes[nextaxistocheck]
            for (; axisnum < axes.Count; axisnum++) if (((tdggroupingaxis)(axes[axisnum])).ischecked) break;
            // count number of active axes under axes[axisnum]
            subaxes = 0;
            for (int i = axisnum + 1; i < axes.Count; i++) if (axes[i].ischecked) subaxes++;


            // if no further active axes, just put pkts into t
            if(subaxes == 0)
            {
                t = new tdgleaf(type, key, parent);
                t.L = new ObservableCollection<PVDisplayObject>();
                foreach (Packet p in pkts) t.L.Add(p);
                return;
            }
            // else group pkts by that axis and assign the groups to parent
            else
            {
                t = new tdgnode(type, key, parent);
                t.L = new ObservableCollection<PVDisplayObject>();

                // group pkts by axes[axisnum]
                List<List<Packet>> query = ((tdggroupingaxis)(axes[axisnum])).groupfn(pkts);
                // foreach group in the result
                foreach (List<Packet> list in query)
                {
                    // create new node - leaf or non-leaf depending on number of active subaxes
                    BuildTreeNode(out tnew, axes[axisnum].type, axes[axisnum].getkey(list[0]), list, axes, axisnum + 1, t);
                    t.L.Add(tnew);
                }
            }

        }



        void tdgaxischeck_Click(object sender, RoutedEventArgs e)
        {
            CheckBox b = (CheckBox)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            BuildTreeNode(out root, null, null, pkts, axes, 0, null);
            root.Lview.Refresh();
        }

        void tdgaxisbutton_Click(object sender, RoutedEventArgs e)
        {
            Button b = (Button)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            List<tdggroupingaxis> mylist = i.parent;
            int pos;
            for (pos = 0; pos < mylist.Count; pos++) if (mylist[pos] == i) break;

            switch (b.Name)
            {
                case "button_top":
                    mylist.RemoveAt(pos);
                    mylist.Insert(0, i); break;
                case "button_up":
                    if (pos == 0) break;
                    mylist.RemoveAt(pos);
                    mylist.Insert(pos - 1, i); break;
                case "button_dn":
                    if (pos == mylist.Count - 1) break;
                    mylist.RemoveAt(pos);
                    mylist.Insert(pos+1, i); break;
                case "button_bot":
                    if (pos == mylist.Count - 1) break;
                    mylist.RemoveAt(pos);
                    mylist.Insert(pos+1, i); break;
                default: break;
            }
            (CollectionViewSource.GetDefaultView(mylist)).Refresh();

            BuildTreeNode(out root, null, null, pkts, axes, 0, null);
            root.Lview.Refresh();

        }

        public void tdg_break_out_Executed(object sender, ExecutedRoutedEventArgs e)
        {


/*            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
                // change grouped_xx to specific value
                // do this for all packets that have this specific value - need to pass through entire packet list

            switch(column)
            {
                case "IP4g":
                    if (p.IP4g == null)
                    {
                        foreach (Packet i in pkts)
                            if (i.SrcIP4 == p.SrcIP4) i.IP4g = i.SrcIP4;
                        BuildTree(tree, pkts, axes, 0);
                        tree.Lview.Refresh();
                    }
                    break;
                default:
                    break;
            }
            */
            
        }
        public void tdg_break_out_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
            /*            DataGrid dg = (DataGrid)sender;
                        string column = dg.CurrentColumn.SortMemberPath;
                        Packet p = (Packet)(dg.CurrentCell.Item);

                        // if grouped for this specific value, then
                        // change grouped_xx to specific value
                        // do this for all packets that have this specific value - need to pass through entire packet list

                        switch (column)
                        {
                            case "SrcIP4":
                                e.CanExecute = (p.IP4g == null);
                                break;
                            default:
                                e.CanExecute = false;
                                break;
                        }
              */
        }

        public void tdg_group_Executed(object sender, ExecutedRoutedEventArgs e)
        {
        /*    DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            Packet p = (Packet)(dg.CurrentCell.Item);

            switch (column)
            {
                case "SrcIP4":
                    if (p.IP4g != null)
                    {
                        foreach (Packet i in pkts)
                            if (i.SrcIP4 == p.SrcIP4) i.IP4g = null;
                        BuildTree(tree, pkts, axes, 0);
                        tree.Lview.Refresh();
                    }
                    break;
                default:
                    break;
            }
            */

        }
        public void tdg_group_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
            /*
            DataGrid dg = (DataGrid)sender;
            string column = dg.CurrentColumn.SortMemberPath;
            Packet p = (Packet)(dg.CurrentCell.Item);

            // if grouped for this specific value, then
            // change grouped_xx to specific value
            // do this for all packets that have this specific value - need to pass through entire packet list

            switch (column)
            {
                case "SrcIP4":
                    e.CanExecute = (p.IP4g != null);
                    break;
                default:
                    e.CanExecute = false;
                    break;
            }
            */
        }

    }


}
