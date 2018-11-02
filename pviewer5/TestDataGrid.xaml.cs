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
using System.Linq.Expressions;

namespace pviewer5
{
    
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
        public virtual int CompareKeys(object a, object b)  // does the CompareTo operation on two values of the key for this axis
            // note: null will be considered higher than any non-null value
            // two nulls will be considered equal
        {
            return 0;
        }

        /*
        public class tdgCompare : IComparer
                // provides comparer  for List<Packet> objects that are the result of the grouping function in the tree builder
                {
                    int IComparer.Compare(object x, object y)
                    {
                        throw new NotImplementedException();
                    }
                }
        */
            
        public virtual void Sorter(List<List<Packet>> L)
        {
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
            var query = pkts.GroupBy<Packet, Protocols?>(x => x.Protocolsg);
            // need to order the query here
            // and in the other groupfns
            
            foreach (var g in query) result.Add(g.ToList<Packet>());
            return result;
        }
        public override object getkey(Packet p)
        {
            return p.Protocolsg;
        }
        public override int CompareKeys(object a, object b)
        {
            // note: null is considered higher than any non-null value, and two nulls are considered equal
            if (a == null) if (b == null) return 0; else return 1; else if (b == null) return -1;
            return ((Protocols)a).CompareTo((Protocols)b);
        }

        public class tdgCompare : IComparer
        // provides comparer  for List<Packet> objects that are the result of the grouping function in the tree builder
        {
            int IComparer.Compare(object a, object b)
            {
                Protocols? akey = ((List<Packet>)a)[0].Protocolsg;
                Protocols? bkey = ((List<Packet>)b)[0].Protocolsg;
                // note: null is considered higher than any non-null value, and two nulls are considered equal
                if (akey == null) if (bkey == null) return 0; else return 1; else if (bkey == null) return -1;
                // now we know akey anb bkey are non-null
                return ((Protocols)akey).CompareTo((Protocols)bkey);
            }
        }
        public override void Sorter(List<List<Packet>> L)
        {
            IComparer comp = new tdgCompare();

            L.Sort(comp.Compare);
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
        public override int CompareKeys(object a, object b)
        {
            // note: null is considered higher than any non-null value, and two nulls are considered equal
            if (a == null) if (b == null) return 0; else return 1; else if (b == null) return -1;
            return ((IP4)a).CompareTo((IP4)b);
        }
        public class tdgCompare : IComparer
        // provides comparer  for List<Packet> objects that are the result of the grouping function in the tree builder
        {
            int IComparer.Compare(object a, object b)
            {
                IP4? akey = ((List<Packet>)a)[0].IP4g;
                IP4? bkey = ((List<Packet>)b)[0].IP4g;
                // note: null is considered higher than any non-null value, and two nulls are considered equal
                if (akey == null) if (bkey == null) return 0; else return 1; else if (bkey == null) return -1;
                // now we know akey anb bkey are non-null
                int r;
                r = ((IP4)akey).CompareTo((IP4)bkey);
                return r;
            }
        }
        public override void Sorter(List<List<Packet>> L)
        {
            IComparer comp = new tdgCompare();

            L.Sort(comp.Compare);
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
        public override int CompareKeys(object a, object b)
        {
            // note: null is considered higher than any non-null value, and two nulls are considered equal
            if (a == null) if (b == null) return 0; else return 1; else if (b == null) return -1;
            return (((Type)a).ToString()).CompareTo(((Type)b).ToString());
        }
        public class tdgCompare : IComparer
        // provides comparer  for List<Packet> objects that are the result of the grouping function in the tree builder
        {
            int IComparer.Compare(object a, object b)
            {
                Type akey = ((List<Packet>)a)[0].PGTypeg;
                Type bkey = ((List<Packet>)b)[0].PGTypeg;
                // note: null is considered higher than any non-null value, and two nulls are considered equal
                if (akey == null) if (bkey == null) return 0; else return 1; else if (bkey == null) return -1;
                // now we know akey anb bkey are non-null
                return akey.ToString().CompareTo(bkey.ToString());
            }
        }
        public override void Sorter(List<List<Packet>> L)
        {
            IComparer comp = new tdgCompare();

            L.Sort(comp.Compare);
        }



    }





    public class tdgnode : PVDisplayObject, IComparable
    {
        public tdggroupingaxis myaxis;
        public object key { get; set; }   // the common value of the key for the axis of this level of the tree for the items in this node
        // commenting out - need L to be able to be tdgnodes or Packets.....  public new ObservableCollection<tdgnode> L { get; set; }  // overrides the base class L because we need to be able to sort these L

        public tdgnode(tdggroupingaxis a, object k, PVDisplayObject par) : base(par)
        {
            myaxis = a;
            key = k;
            // instantiate the child list
            // commenting out - instantiation will now happen in tree builder.... L = new ObservableCollection<tdgnode>();
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

        public int CompareTo(object obj)
        {
            return (myaxis.CompareKeys(key, ((tdgnode)obj).key));
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

         public TestDataGrid()
        {
            Packet p;

            InitializeComponent();
            tdggrid.DataContext = this;


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

        }





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

                tleafnew.L = new ObservableCollection<PVDisplayObject>();
                foreach (Packet p in pkts)
                {
                    p.Parent = tleafnew;
                    tleafnew.L.Add(p);
                }
                tleafnew.Lview = (ListCollectionView)CollectionViewSource.GetDefaultView(tleafnew.L);
                // next line seems to be obsolete, can't remember what it was for
                // tleafnew.Lview.GroupDescriptions.Add(new PropertyGroupDescription(axes[thisaxis].groupingpropertyname));
                return tleafnew;
            }
            else    // else recursively build children
            {
                // if this node is the root...
                if (par == null) tnodenew = new tdgnode(null, null, null);
                // else..
                else tnodenew = new tdgnode(axes[thisaxis], axes[thisaxis].getkey(pkts[0]), par);

                tnodenew.L = new ObservableCollection<PVDisplayObject>();

                // group pkts by axes[nextaxis]
                List<List<Packet>> query = ((tdggroupingaxis)(axes[nextaxis])).groupfn(pkts);
                axes[nextaxis].Sorter(query);
                // foreach group in the result, add it as a child
                foreach (List<Packet> list in query) tnodenew.L.Add(BuildTreeNode2(tnodenew, list));
                
                return tnodenew;
            }

        }



        tdgnode MergeAllChildren(tdgnode t, int expansionstatemergerule)
        // this is to handle the case of removing an axis from the hierarchy
        // this function will be executed on each node on the axis above the axis that is being removed
        // merges all children of t into a single tdgnode
        // returns the new node
        // the caller will replace t with tnew in the tree

        // expansion state of new node controlled by value of expansionstatemergerule:
        //    1 = always use a's
        //    2 = always use b's
        //    3 = if either expanded, then expand
        //    4 = if either not expanded, then not expanded
        //    5 = always expand
        //    6 = always not expanded
        {
            tdgnode tnew = new tdgnode(t.myaxis, t.key, t.Parent);

            tnew.L = new ObservableCollection<PVDisplayObject>();

            // if next axis down is leaves, just concatenate all the packet lists
            if (t.L[0].GetType() == typeof(tdgleaf))
            {
                int counter = 1;
                tnew.L = t.L[0].L;
                while (counter < t.L.Count())
                {
                    tnew.L.Concat(t.L[counter].L);
                }
            }
            // else do MergeTwoNodes over t.L
            else
            {
                int counter = 1;
                tnew = (tdgnode)t.L[0];
                while (counter < t.L.Count())
                {
                    MergeTwoNodes(tnew, (tdgnode)t.L[counter], expansionstatemergerule);
                }
            }

            return tnew;
        }



        void MergeTwoNodes(tdgnode a, tdgnode b, int expansionstatemergerule)
            // this is to handle the case where two trees are being merged, e.g., when a new set of packets is loaded and needs to be merged into the existing tree
            // merges node b into node a
            // checks that myaxis and key match for a and b - THIS SHOULD NEVER HAPPEN
            // expansion state of new node controlled by value of expansionstatemergerule
        {

            if ((a.myaxis != b.myaxis) | (a.key != b.key)) MessageBox.Show("trying to merge two nodes with mismatched axis or key values - THIS SHOULD NEVER HAPPEN");

            // if a and b are leaves, then just merge the packets in their L's
            if (a.GetType() == typeof(tdgleaf))
            {
                a.L.Concat(b.L);
            }
            // else for each child of b, add it to a.L
            // take advantage of fact that the L's are sorted, so we do not need to search a.L for each b.L
            else
            {
                //   if a.L has a node with same key, then merge them
                //   else insert into a.L
                int ai = 0;
                bool merged;
                foreach (tdgnode n in b.L)
                {
                    // find position for n in a.L
                    // then either merge it or insert it
                    // if get to end of a.L without being merged, add it on to end of a.L
                    merged = false;
                    while (ai < a.L.Count())
                    {
                        if (n.CompareTo(a.L[ai]) == 0)
                        {
                            MergeTwoNodes((tdgnode)a.L[ai], n, expansionstatemergerule);
                            merged = true;
                            break;
                        }
                        else if (n.CompareTo(a.L[ai]) < 0)
                        {
                            a.L.Insert(ai, n);
                            merged = true;
                            break;
                        }
                        ai++;
                    }
                    if (!merged) a.L.Add(n);
                }
            }

            // set expansion state of merged a
            switch(expansionstatemergerule)
            {
                default:
                case 1:
                    // no-op - just keeping a's the same
                    break;
                case 2:
                    a.IsExpanded = b.IsExpanded;
                    break;
                case 3:
                    a.IsExpanded = a.IsExpanded | b.IsExpanded;
                    break;
                case 4:
                    a.IsExpanded = a.IsExpanded & b.IsExpanded;
                    break;
                case 5:
                    a.IsExpanded = true;
                    break;
                case 6:
                    a.IsExpanded = false;
                    break;
            }

        }


        tdgnode BreakItemOut(tdgnode t, object breakoutkey)
            // t is a node where the key is null because it contains grouped, i.e., not-broken-out items
        {
            return null;
        }



        /*
         * now need functions for
         * 1) BreakItemOutOfNode - for nodes where key==null and one of the axis items needs to be split out
         * 2) SplitNodeOnNewAxis - for case where a new axis is activated
         * 3) something to handle gropu and breakout commands
         

            */




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

            if (menu.PlacementTarget.GetType() == typeof(DataGrid))
            {
                DataGrid dg = (DataGrid)menu.PlacementTarget;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);

                foreach (Packet i in pkts)
                    if (i.SrcIP4 == p.SrcIP4) i.IP4g = i.SrcIP4;
                List<Packet> newlist = new List<Packet>();
                foreach (tdgnode t in p.Parent.Parent.L)
                    foreach (Packet pp in t.L) newlist.Add(pp);

                BuildTreeNode2((tdgnode)p.Parent.Parent, newlist);
                p.Parent.Parent.Lview.Refresh();


            }
            else if (menu.PlacementTarget.GetType() == typeof(TextBlock))
            {
                tdgnode node = (tdgnode)(e.Parameter);
            }

            // if grouped for this specific value, then
                // change grouped_xx to specific value
                // do this for all packets that have this specific value - need to pass through entire packet list
/*
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
