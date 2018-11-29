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
        public virtual object getkeyunderlying(Packet p)
        // gets the underlying value used for the key field (i.e., not the one that is set to null if the packet is grouped)
        {
            return null;
        }
        public virtual void setkey(Packet p, object v)
        {

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
        public override object getkeyunderlying(Packet p)
        {
            return p.ProtOuter;
        }
        public override void setkey(Packet p, object v)
        {
            p.Protocolsg = (Protocols?)v;
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
        public override object getkeyunderlying(Packet p)
        {
            return p.SrcIP4;
        }
        public override void setkey(Packet p, object v)
        {
            p.IP4g = (IP4?)v;
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
        public override object getkeyunderlying(Packet p)
        {
            return p.PGType;
        }
        public override void setkey(Packet p, object v)
        {
            p.PGTypeg = (Type)v;
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


            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b04; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.DNS; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b04; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = null; p.SrcIP4 = 0xc0a80b03; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b05; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b06; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.ARP; p.PGTypeg = typeof(ARPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);
            p = new Packet(); p.IP4g = p.SrcIP4 = 0xc0a80b02; p.Protocolsg = p.ProtOuter = Protocols.TCP; p.PGTypeg = typeof(HTTPG); pkts.Add(p);

            axes.Add(new tdggroupingaxisprot(axes));
            axes.Add(new tdggroupingaxispgtype(axes));
            axes.Add(new tdggroupingaxisip4(axes));

            root = new ObservableCollection<tdgnode>();
            root.Add(BuildTreeNode2(null, pkts));

        }





        tdgnode BuildTreeNode2(tdgnode par, List<Packet> pkts)
        // builds out node or leaf under par, using pkts
        // returns the new node - caller must add the node to the tree
        // also handles special case of par == null, which means this is the root node
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
            if (nextaxis >= axes.Count)
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
        // merges all children of t and returns a new node that can replace t
        // caller must replace t in the tree

        // expansion state of new node controlled by value of expansionstatemergerule:
        //    1 = always use a's
        //    2 = always use b's
        //    3 = if either expanded, then expand
        //    4 = if either not expanded, then not expanded
        //    5 = always expand
        //    6 = always not expanded
        {

            // if next axis down is leaves, just concatenate all the packet lists
            if (t.L[0].GetType() == typeof(tdgleaf))
            {
                tdgleaf newleaf = new tdgleaf(t.myaxis, t.key, t.Parent);
                newleaf.L = new ObservableCollection<PVDisplayObject>();
                foreach (tdgleaf l in t.L) foreach (Packet p in l.L) newleaf.L.Add(p);
                newleaf.Parent = t.Parent;
                newleaf.myaxis = t.myaxis;
                newleaf.key = t.key;
                return newleaf;
            }
            // else do MergeTwoNodes over t.L
            else
            {
                tdgnode tnew, tnew2;
                tnew = (tdgnode)t.L[0];

                for (int counter = 1; counter < t.L.Count(); counter++)
                {
                    tnew2 = (tdgnode)t.L[counter];
                    tnew = MergeTwoNodes(tnew, tnew2, expansionstatemergerule);
                }

                tnew.Parent = t.Parent;
                tnew.myaxis = t.myaxis;
                tnew.key = t.key;

                return tnew;
            }

        }



        tdgnode MergeTwoNodes(tdgnode a, tdgnode b, int expansionstatemergerule)
            // this is to handle the case where two trees are being merged, e.g.,
            //      when a new set of packets is loaded and needs to be merged into the existing tree
            //      when a item is being grouped into the "other" node
            //      when an axis is being removed and MergeAllChildren needs to merge over L
            // this function merges node b into node a
            // CALLER MUST PRUNE b from tree
            // checks that myaxis matches for a and b - THIS SHOULD ALWAYS BE THE TRUE
            // expansion state of new node controlled by value of expansionstatemergerule
        {
            if (a.myaxis != b.myaxis) MessageBox.Show("trying to merge two nodes with mismatched axis value - THIS SHOULD NEVER HAPPEN");

            // if a and b are leaves, then just merge the packets in their L's
            if (a.GetType() == typeof(tdgleaf))
            {
                foreach (Packet p in b.L)
                {
                    p.Parent = a;
                    a.L.Add(p);
                }
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
                    n.Parent = a;

                    while (ai < a.L.Count())
                    {
                        if (n.CompareTo(a.L[ai]) == 0)
                        {
                            a.L[ai] = MergeTwoNodes((tdgnode)a.L[ai], n, expansionstatemergerule);
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

            // return the merged node
            return a;

        }

        tdgnode DeactivateAxis(tdgnode t, tdggroupingaxis ax)
        // remove axis from tree under t
        // return value is node that should replace t
        // caller must do the replacement
        {
            tdgnode tnew;

            if (((tdgnode)(t.L[0])).myaxis == ax)
            {
                tnew = MergeAllChildren(t, 3);
                RefreshViews(tnew);
                return tnew;
            }
            else
            {
                for (int i = 0; i < t.L.Count(); i++) t.L[i] = DeactivateAxis((tdgnode)t.L[i], ax);
                return t;
            }
        }


        void BreakItemOut(tdgnode par, tdggroupingaxis ax, object key)
        // break out item key on axis ax, underneath node par (i.e., assumes that axis ax is not at par or above it)
        // broken-out nodes will be un-expanded
        // do nothing if we get to leaves without finding axis ax
        {

            // if par is on ax, break out key
            if (((tdgnode)(par.L[0])).myaxis == ax)
            {
                tdgnode tother = null;
                List<Packet> pkts = new List<Packet>();

                // find node for other
                foreach (tdgnode t in par.L)
                {
                    if (t.key == null) tother = t;
                    // check that key is currently not broken out - throw an error if so, this should never happen
                    if (t.key == key) MessageBox.Show("trying to break out an item that is already broken out - THIS SHOULD NEVER HAPPEN");
                }
                // if there is an other node, strip out packets that are to be broken out
                if (tother != null)
                {
                    // call recursive function to split out packets to be broken out
                    // handle return value of FALSE, which indicates the "other" node is now empty and should be pruned
                    if (!StripPacketsToBreakOut(pkts, tother, ax, key)) par.L.Remove(tother);
                    if (pkts.Count > 0)
                    {
                        // build new subtree under par with the broken out packets
                        tdgnode tnew = BuildTreeNode2(par, pkts);
                        // insert it in par.L in sort order
                        int i = 0;
                        for (; i < par.L.Count(); i++) if (ax.CompareKeys(key, ((tdgnode)(par.L[i])).key) < 0) break;
                        par.L.Insert(i, tnew);
                    }
                }
            }

            // else recurse down through the tree
            else foreach (tdgnode t in par.L) BreakItemOut(t, ax, key);

        }

        bool StripPacketsToBreakOut(List<Packet> pkts, tdgnode t, tdggroupingaxis ax, object key)
        // recursive function to assemble list of packets to break out
        // each call will either move down one level in the tree and call itself recursively,
        // or return after having moved packets to break out from t to pkts argument
        // return value is TRUE if there are still packets in the other node, FALSE otherwise
        // caller will have to handle when this function returns FALSE by pruning empty nodes
        {
            if (t.GetType() == typeof(tdgleaf))
            {
                ObservableCollection<PVDisplayObject> otherpkts = new ObservableCollection<PVDisplayObject>();
                foreach (Packet p in t.L)
                {
                    // if p is to be broken out
                    if (ax.CompareKeys(ax.getkeyunderlying(p), key) == 0)
                    {
                        // change grouping axis value from null to actual value
                        ax.setkey(p, key);
                        // append to pkts
                        pkts.Add(p);
                    }
                    // else append to otherpkts
                    else otherpkts.Add(p);
                }
                // if otherpkts is empty, clear t.L and return false
                if (otherpkts.Count()==0)
                {
                    t.L.Clear();
                    return false;
                }
                // else replace t.L with otherpkts and return true
                else
                {
                    t.L = otherpkts;
                    return true;
                }
            }
            else // t is not a leaf, recurse down through next level of tree
            {
                ObservableCollection<PVDisplayObject> newL = new ObservableCollection<PVDisplayObject>();
                foreach (tdgnode tt in t.L) if (StripPacketsToBreakOut(pkts, tt, ax, key)) newL.Add(tt);
                t.L = newL;
                return (t.L.Count() != 0);
            }



        }

        void GroupItem(tdgnode par, tdggroupingaxis ax, object key)
        // group item key on axis ax, underneath node par (i.e., assumes that axis ax is not at par or above it)
        // if group node exists already, use its expansion state
        // do nothing if we get to leaves without finding axis ax
        {

            // if axes below par is ax, group item with chosen key
            if (((tdgnode)(par.L[0])).myaxis == ax)
            {
                tdgnode tother = null;
                tdgnode ttogroup = null;

                // find node for other
                foreach (tdgnode t in par.L)
                {
                    if (t.key == null) tother = t;
                    if (ax.CompareKeys(t.key, key)==0) ttogroup = t;
                }
                if (ttogroup != null)
                {
                    // change packet keys to null
                    ChangePacketKeys(ttogroup, ax, null);
                    par.L.Remove(ttogroup);
                    // if there is an other node already, merge new item into it
                    if (tother != null) MergeTwoNodes(tother, ttogroup, 1);
                    // else, t to group just becomes the other node
                    else
                    {
                        ttogroup.key = null;
                        par.L.Add(ttogroup);
                    }
                }
            }

            // else recurse down through the tree
            else foreach (tdgnode t in par.L) GroupItem(t, ax, key);

        }

        tdgnode ActivateNewAxis(tdgnode t, tdggroupingaxis newaxis)
        // recursively walk down tree to nodes above the new axis
        // if new axis is to be the child of t, build a replacement for t and return it - the caller will do the replacement
        {
            // identify next active axis AFTER t.myaxis
            // find index of next axis *after* t.myaxis - note that if t.myaxis is null because t is the root node, then IndexOf will return -1
            int i = axes.IndexOf(t.myaxis) + 1;
            // find next active axis
            while (!axes[i].ischecked) i++;

            // if next active axis is newaxis, then build new tree under t
            if (axes[i] == newaxis)
            {
                // gather all packets at leaves into a list
                List<Packet> pkts = new List<Packet>();
                GatherPackets(t, pkts);
                // build new tree at t
                t = BuildTreeNode2((tdgnode)t.Parent, pkts);
                RefreshViews(t);
                return t;
            }
            // else recurse down through t.L
            else
            {
                for (int ii = 0; ii < t.L.Count(); ii++) t.L[ii] = ActivateNewAxis((tdgnode)t.L[ii], newaxis);
                return t;
            }

        }

        void ChangePacketKeys(tdgnode t, tdggroupingaxis ax, object newkey)
        // recursively go down tree under t until reach packets
        // then change all packets' key values on ax to newkey
        {
            if (t.GetType() == typeof(tdgleaf)) foreach (Packet p in t.L) ax.setkey(p, newkey);
            else foreach (tdgnode tt in t.L) ChangePacketKeys(tt, ax, newkey);
        }


        void GatherPackets(tdgnode t, List<Packet>pkts)
        // recurse down tree under t and gather all packets into pkts
        // used by ActivateNewAxis
        {
            if (t.GetType() == typeof(tdgleaf)) foreach (PVDisplayObject p in t.L) pkts.Add((Packet)p);
            else foreach (tdgnode tt in t.L) GatherPackets(tt, pkts);
        }



        void RefreshViews(tdgnode t)
        {
            if (t.GetType() != typeof(tdgleaf)) foreach (tdgnode tt in t.L) RefreshViews(tt);
            t.Lview.Refresh();
        }


        void tdgaxischeck_Click(object sender, RoutedEventArgs e)
        {
            CheckBox b = (CheckBox)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            if (b.IsChecked == true) root[0] = ActivateNewAxis(root[0], i);
            else root[0] = DeactivateAxis(root[0], i);
        }

        void tdgaxisbutton_Click(object sender, RoutedEventArgs e)
        {
            Button b = (Button)sender;
            tdggroupingaxis ax = (tdggroupingaxis)b.DataContext;

            List<tdggroupingaxis> axlist = ax.parent;
            int pos = axlist.IndexOf(ax);

            if (ax.ischecked) root[0] = DeactivateAxis(root[0], ax);

            switch (b.Name)
            {
                case "button_top":
                    axlist.RemoveAt(pos);
                    axlist.Insert(0, ax);
                    break;
                case "button_up":
                    if (pos == 0) break;
                    axlist.RemoveAt(pos);
                    axlist.Insert(pos - 1, ax);
                    break;
                case "button_dn":
                    if (pos == axlist.Count - 1) break;
                    axlist.RemoveAt(pos);
                    axlist.Insert(pos+1, ax);
                    break;
                case "button_bot":
                    if (pos == axlist.Count - 1) break;
                    axlist.RemoveAt(pos);
                    axlist.Add(ax);
                    break;
                default: break;
            }

            if (ax.ischecked) root[0] = ActivateNewAxis(root[0], ax);
            // also refresh axis list view
            (CollectionViewSource.GetDefaultView(axlist)).Refresh();

        }

        public void tdg_break_out_Executed(object sender, ExecutedRoutedEventArgs e)
        {

            ContextMenu menu = (ContextMenu)sender;

            if (menu.PlacementTarget.GetType() == typeof(DataGrid))
            {
                DataGrid dg = (DataGrid)menu.PlacementTarget;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);
                tdggroupingaxis ax = null;
                object key;

                switch (col.Header)
                {
                    case "IP":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisip4)) ax = a;
                        key = p.SrcIP4;
                        BreakItemOut(root[0], ax, key);
                        break;
                    case "Proto":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisprot)) ax = a;
                        key = p.ProtOuter;
                        BreakItemOut(root[0], ax, key);
                        break;
                    case "GroupType":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxispgtype)) ax = a;
                        key = p.PGType;
                        BreakItemOut(root[0], ax, key);
                        break;
                    default:
                        break;
                }


            }
            // no else clause, since breakout cannot be initiated from a tree node

        }

    
        public void tdg_break_out_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {

            ContextMenu menu = (ContextMenu)sender;

            if (menu.PlacementTarget == null)
            {
                e.CanExecute = false;
                return;
            }

            if (menu.PlacementTarget.GetType() == typeof(DataGrid))
            {

                // default return value is false
                // tests below will set to true if BOTH axis is active AND packet key is null
                e.CanExecute = false;

                DataGrid dg = (DataGrid)menu.PlacementTarget;
                // check if datagrid is empty and return now if so
                // this can happen after a break out or group operation reduces a datagrid to empty
                // the system seems to try to do another "can execute" test after the command has executed
                if (dg.ItemsSource == null) return;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);

                switch (col.Header)
                {
                    case "IP":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisip4)) if (a.ischecked) e.CanExecute = (p.IP4g == null);
                        break;
                    case "Proto":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisprot)) if (a.ischecked) e.CanExecute = (p.Protocolsg == null);
                        break;
                    case "GroupType":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxispgtype)) if (a.ischecked) e.CanExecute = (p.PGTypeg == null);
                        break;
                }
            }
            else if (menu.PlacementTarget.GetType() == typeof(TextBlock))
            {
                // always return false
                // it is not meaningful to do a break out command on a tree node - there is no way to know which item is to be broken out

                e.CanExecute = false;
            }
            
        }

        public void tdg_group_Executed(object sender, ExecutedRoutedEventArgs e)
        {

            ContextMenu menu = (ContextMenu)sender;

            if (menu.PlacementTarget.GetType() == typeof(DataGrid))
            {
                DataGrid dg = (DataGrid)menu.PlacementTarget;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);
                tdggroupingaxis ax = null;
                object key;

                switch (col.Header)
                {
                    case "IP":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisip4)) ax = a;
                        key = p.SrcIP4;
                        GroupItem(root[0], ax, key);
                        break;
                    case "Proto":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisprot)) ax = a;
                        key = p.ProtOuter;
                        GroupItem(root[0], ax, key);
                        break;
                    case "GroupType":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxispgtype)) ax = a;
                        key = p.PGType;
                        GroupItem(root[0], ax, key);
                        break;
                    default:
                        break;
                }
            }

            else if (menu.PlacementTarget.GetType() == typeof(TextBlock))
            {
                tdgnode node = (tdgnode)(e.Parameter);


            }

        }



        public void tdg_group_CanExecute(object sender, CanExecuteRoutedEventArgs e)
        {

            ContextMenu menu = (ContextMenu)sender;

            if (menu.PlacementTarget == null)
            {
                e.CanExecute = false;
                return;
            }

            if (menu.PlacementTarget.GetType() == typeof(DataGrid))
            {

                // default return value is false
                // tests below will set to true if BOTH axis is active AND packet key is not null
                e.CanExecute = false;    
                
                DataGrid dg = (DataGrid)menu.PlacementTarget;
                // check if datagrid is empty and return now if so
                // this can happen after a break out or group operation reduces a datagrid to empty
                // the system seems to try to do another "can execute" test after the command has executed
                if (dg.ItemsSource == null) return;
                DataGridTextColumn col = (DataGridTextColumn)(dg.SelectedCells[0].Column);
                Packet p = (Packet)(dg.SelectedCells[0].Item);
                
                switch (col.Header)
                {
                    case "IP":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisip4)) if (a.ischecked) e.CanExecute = (p.IP4g != null);
                        break;
                    case "Proto":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxisprot)) if (a.ischecked) e.CanExecute = (p.Protocolsg != null);
                        break;
                    case "GroupType":
                        foreach (tdggroupingaxis a in axes) if (a.GetType() == typeof(tdggroupingaxispgtype)) if (a.ischecked) e.CanExecute = (p.PGTypeg != null);
                        break;

                }
            }
            else if (menu.PlacementTarget.GetType() == typeof(TextBlock))
            {
                tdgnode node = (tdgnode)(e.Parameter);

                if (node == null)
                {
                    e.CanExecute = false;
                    return;
                }
                e.CanExecute = (node.key != null);
            }
        }

    }


}
