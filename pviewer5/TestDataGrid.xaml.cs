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
        public string groupingpropertyname { get; set; }
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public List<tdggroupingaxis> parent { get; set; }

        public tdggroupingaxis(List<tdggroupingaxis> par)
        {
            type = typeof(object);
            groupingpropertyname = null;
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
            groupingpropertyname = "Protocolsg";
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
            groupingpropertyname = "IP4g";
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
            groupingpropertyname = "PGTypeg";
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
        public tdggroupingaxis myaxis;
        public object key { get; set; }   // the common value of the key for the axis of this level of the tree for the items in this node

        public tdgnode(tdggroupingaxis a, object k, PVDisplayObject par) : base(par)
        {
            myaxis = a;
            key = k;
            // instantiate the child list
            L = new ObservableCollection<PVDisplayObject>();
        }
        public override string displayinfo
        {
            get
            {
                if (myaxis == null) return "ROOT";
                if (myaxis.type == null) return "Unknown";
                else if (myaxis.type == typeof(IP4?)) return "IP4 address = " + ((key == null) ? "All Other" : ((IP4?)key).ToString());
                else if (myaxis.type == typeof(Protocols?)) return "Protocol = " + ((key == null) ? "All Other" : ((Protocols?)key).ToString());
                else if (myaxis.type == typeof(Type)) return "Packet Group Type = " + ((key == null) ? "All Other" : ((Type)key).ToString());
                else return "Unknown";
            }
        }
    }

    public class tdgleaf : tdgnode
    {
        public tdgleaf(tdggroupingaxis a, object k, PVDisplayObject par) : base(a, k, par)
        {
        }
    }


    public partial class TestDataGrid : Window
    {
        public ObservableCollection<tdgnode> root { get; set; }     // this has to be a list so that it will bind correctly to TreeView
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

            //tdg_break_out_binding = new CommandBinding(tdg_break_out_cmd, tdg_break_out_Executed, tdg_break_out_CanExecute);
            //tdg_group_binding     = new CommandBinding(tdg_group_cmd,     tdg_group_Executed,     tdg_group_CanExecute);
            //tdgtree.CommandBindings.Add(tdg_break_out_binding);
            //tdgtree.CommandBindings.Add(tdg_group_binding);

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

            root = new ObservableCollection<tdgnode>();
            root.Add(BuildTreeNode2(null, pkts));
            
            /*

            NEXT ISSUES:
                2) LEAF DATAGRID SHOULD HAVE A HEADER
                3) LEAF DATAGRID SHOULD BE COLLAPSED BY DEFAULT
                4) HOOK UP THE CONTEXT MENUS
                */

        }





        /*
         * notes on clarifying design
         * seems like only need two types, because need two different data templates to bind in the xaml
         *      node: when children have an axis, template is treeview
         *      leaf: when children have no axis, template is datagrid with title bar
         *          title bar will have displayinfo
         *  displayinfo property should produce an appropriate string for each of the four case above
         *  
         */

        tdgnode BuildTreeNode2(tdgnode par, List<Packet> pkts)
        // builds out node or leaf under parent
        // also handles special case of parent == null, which means this is the root node
        // nodes in the tree have an axis they belong to, and an axis for their children
        // either of these can be null
        // four cases:
        //       root:  own axis is null, child axis non-null
        //       leaf:  own axis non-null, child axis null
        //       middle:  own axis non-null, child axis non-null
        //       root and leaf:  own axis null, child axis null
        //       
        {
            tdgnode tnodenew;
            tdgleaf tleafnew;

            int paraxis;    // index of axis that parent is on
            int thisaxis;   // index of axis this node is on
            int nextaxis;   // index of axis that children are on

            if (par == null)  // this is the root
            {
                paraxis = -1;
                thisaxis = -1;
            }
            else   // this is not the root, so determine paraxis and thisaxis based on the parent
            {
                if (par.myaxis == null) paraxis = -1;  // if this is a child of the root
                else paraxis = axes.IndexOf(par.myaxis);
                // now set thisaxis based on searching list of axes starting at paraxis+1
                for (thisaxis = paraxis + 1; thisaxis < axes.Count; thisaxis++) if (axes[thisaxis].ischecked) break;
            }

            // now set nextaxis
            for (nextaxis = thisaxis + 1; nextaxis < axes.Count; nextaxis++) if (axes[nextaxis].ischecked) break;

            // if this is a leaf, just put pkts in L
            if (nextaxis == axes.Count)
            {
                // if this node is the root, create leaf with no parent info
                if (par == null) tleafnew = new tdgleaf(null, null, null);
                // else create new regular leaf node
                else tleafnew = new tdgleaf(axes[thisaxis], axes[thisaxis].getkey(pkts[0]), par);
                foreach (Packet p in pkts) tleafnew.L.Add(p);
                tleafnew.Lview = (ListCollectionView)CollectionViewSource.GetDefaultView(tleafnew.L);
                tleafnew.Lview.GroupDescriptions.Add(new PropertyGroupDescription(axes[thisaxis].groupingpropertyname));
                return tleafnew;
            }
            else    // else recursively build children
            {
                // if this node is the root...
                if (par == null) tnodenew = new tdgnode(null, null, null);
                // else..
                else tnodenew = new tdgnode(axes[thisaxis], axes[thisaxis].getkey(pkts[0]), par);

                // group pkts by axes[nextaxis]
                List<List<Packet>> query = ((tdggroupingaxis)(axes[nextaxis])).groupfn(pkts);
                
                // foreach group in the result, add it as a child
                foreach (List<Packet> list in query) tnodenew.L.Add(BuildTreeNode2(tnodenew, list));
        
                return tnodenew;
            }


        }



        void tdgaxischeck_Click(object sender, RoutedEventArgs e)
        {
            CheckBox b = (CheckBox)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            root[0] = BuildTreeNode2(null, pkts);
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

            root[0] = BuildTreeNode2(null, pkts);
        }

        public void tdg_break_out_Executed(object sender, ExecutedRoutedEventArgs e)
        {

            ContextMenu menu = (ContextMenu)sender;

            if (menu.PlacementTarget.GetType() == typeof (DataGrid))
            {


                DataGrid dg = (DataGrid)menu.PlacementTarget;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);
            }
            else if (menu.PlacementTarget.GetType() == typeof(TextBlock))
            {
                tdgnode node = (tdgnode)(e.Parameter);
            }
/*
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
