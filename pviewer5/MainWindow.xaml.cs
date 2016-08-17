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



    public partial class MainWindow : Window, INotifyPropertyChanged
	{
        public static MainWindow Instance = null;
        
        // properties for packet list view
        public PacketViewer pview;
        private string _packetfilename = null;
        public string PacketFileName { get { return _packetfilename; } set { _packetfilename = value; NotifyPropertyChanged(); } }
        private bool _fileloaded = false;
        public bool FileLoaded { get { return _fileloaded; } set { _fileloaded = value; NotifyPropertyChanged(); } }
        public ObservableCollection<Packet> pkts { get; set; }
        public PVDisplayObject grouplistlist { get; set; }
        public ListCollectionView gllview;
        public ListCollectionView idmview;



        // properties for filter view
        public FilterSet filters { get; set; }

        // properties for domain map view
        public IPDNMap idm { get; set; } = new IPDNMap();
        CommandBinding idmdelrowbinding;
        CommandBinding idmsavebinding;
        CommandBinding idmsaveasbinding;
        CommandBinding idmloadbinding;
        CommandBinding idmmergebinding;

        // properties for ip4 map view
        public IP4AliasMap inm { get; set; } = new IP4AliasMap();
        CommandBinding inmaddrowbinding;
        CommandBinding inmdelrowbinding;
        CommandBinding inmsavebinding;
        CommandBinding inmsaveasbinding;
        CommandBinding inmloadbinding;
        CommandBinding inmappendbinding;

        // properties for mac map view
        public MACAliasMap mnm { get; set; } = new MACAliasMap();
        CommandBinding mnmaddrowbinding;
        CommandBinding mnmdelrowbinding;
        CommandBinding mnmsavebinding;
        CommandBinding mnmsaveasbinding;
        CommandBinding mnmloadbinding;
        CommandBinding mnmappendbinding;

        public MainWindow()
        {
            if (Instance != null) MessageBox.Show("Trying to create a second MainWindow object - THIS SHOULD NEVER HAPPEN");
            else Instance = this;

            // initialize window
            InitializeComponent();
            gridmain.DataContext = this;

            // set up packet list view
            pkts = new ObservableCollection<Packet>();
            grouplistlist = new PVDisplayObject(null);
            grouplistlist.L = new ObservableCollection<PVDisplayObject>();
            gllview = (ListCollectionView)CollectionViewSource.GetDefaultView(grouplistlist.L);
            grouplistlist.L.Add(new DNSGList("DNS Groups", grouplistlist));
            grouplistlist.L.Add(new DHCP4GList("DHCP4 Groups", grouplistlist));
            grouplistlist.L.Add(new TCPGList("TCP Groups", grouplistlist));
            grouplistlist.L.Add(new UDPGList("UDP Groups", grouplistlist));
            grouplistlist.L.Add(new ARPGList("ARP Groups", grouplistlist));
            grouplistlist.L.Add(new GList("Ungrouped Packets", grouplistlist));
            
            // set up filter view
            filters = new FilterSet();
            try
            {
                filters.LoadFromDisk("c:\\pviewer\\autosave.filterset");
            }
            catch { }
            filters.Filename = null;    // reset the filename to null after loading from autosave file

            // set up domain map view
            idm.dg = IDMDG;
            idmview = (ListCollectionView)CollectionViewSource.GetDefaultView(idm.dg.ItemsSource);
            idmdelrowbinding = new CommandBinding(IPDNMap.idmdelrow, IPDNMap.idmExecuteddelrow, IPDNMap.idmCanExecutedelrow);
            idmsavebinding = new CommandBinding(IPDNMap.idmsave, IPDNMap.idmExecutedsave, IPDNMap.idmCanExecutesave);
            idmsaveasbinding = new CommandBinding(IPDNMap.idmsaveas, IPDNMap.idmExecutedsaveas, IPDNMap.idmCanExecutesaveas);
            idmmergebinding = new CommandBinding(IPDNMap.idmmerge, IPDNMap.idmExecutedmerge, IPDNMap.idmCanExecutemerge);
            idmloadbinding = new CommandBinding(IPDNMap.idmload, IPDNMap.idmExecutedload, IPDNMap.idmCanExecuteload);

            // set up ip4 map view
            inm.dg = INMDG;
            inmaddrowbinding = new CommandBinding(IP4AliasMap.inmaddrow, IP4AliasMap.inmExecutedaddrow, IP4AliasMap.inmCanExecuteaddrow);
            inmdelrowbinding = new CommandBinding(IP4AliasMap.inmdelrow, IP4AliasMap.inmExecuteddelrow, IP4AliasMap.inmCanExecutedelrow);
            inmsavebinding = new CommandBinding(IP4AliasMap.inmsave, IP4AliasMap.inmExecutedsave, IP4AliasMap.inmCanExecutesave);
            inmsaveasbinding = new CommandBinding(IP4AliasMap.inmsaveas, IP4AliasMap.inmExecutedsaveas, IP4AliasMap.inmCanExecutesaveas);
            inmappendbinding = new CommandBinding(IP4AliasMap.inmappend, IP4AliasMap.inmExecutedappend, IP4AliasMap.inmCanExecuteappend);
            inmloadbinding = new CommandBinding(IP4AliasMap.inmload, IP4AliasMap.inmExecutedload, IP4AliasMap.inmCanExecuteload);

            inmgrid.CommandBindings.Add(inmaddrowbinding);
            inmgrid.CommandBindings.Add(inmdelrowbinding);
            inmgrid.CommandBindings.Add(inmsavebinding);
            inmgrid.CommandBindings.Add(inmsaveasbinding);
            inmgrid.CommandBindings.Add(inmappendbinding);
            inmgrid.CommandBindings.Add(inmloadbinding);
            inmaddrowmenuitem.CommandTarget = inmgrid;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model, and it seems the data grid (and even the whole window) do not have keyboard focus when the application starts up
            inmdelrowmenuitem.CommandTarget = inmgrid;   // ditto

            // set up mac map view
            mnm.dg = MNMDG;
            mnmaddrowbinding = new CommandBinding(MACAliasMap.mnmaddrow, MACAliasMap.mnmExecutedaddrow, MACAliasMap.mnmCanExecuteaddrow);
            mnmdelrowbinding = new CommandBinding(MACAliasMap.mnmdelrow, MACAliasMap.mnmExecuteddelrow, MACAliasMap.mnmCanExecutedelrow);
            mnmsavebinding = new CommandBinding(MACAliasMap.mnmsave, MACAliasMap.mnmExecutedsave, MACAliasMap.mnmCanExecutesave);
            mnmsaveasbinding = new CommandBinding(MACAliasMap.mnmsaveas, MACAliasMap.mnmExecutedsaveas, MACAliasMap.mnmCanExecutesaveas);
            mnmappendbinding = new CommandBinding(MACAliasMap.mnmappend, MACAliasMap.mnmExecutedappend, MACAliasMap.mnmCanExecuteappend);
            mnmloadbinding = new CommandBinding(MACAliasMap.mnmload, MACAliasMap.mnmExecutedload, MACAliasMap.mnmCanExecuteload);

            mnmgrid.CommandBindings.Add(mnmaddrowbinding);
            mnmgrid.CommandBindings.Add(mnmdelrowbinding);
            mnmgrid.CommandBindings.Add(mnmsavebinding);
            mnmgrid.CommandBindings.Add(mnmsaveasbinding);
            mnmgrid.CommandBindings.Add(mnmappendbinding);
            mnmgrid.CommandBindings.Add(mnmloadbinding);
            mnmaddrowmenuitem.CommandTarget = mnmgrid;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model, and it seems the data grid (and even the whole window) do not have keyboard focus when the application starts up
            mnmdelrowmenuitem.CommandTarget = mnmgrid;   // ditto


            // try to restore window position and other settings - see "Programming WPF Second Edition" page 321
            try
            {
                Rect bounds = Properties.Settings.Default.WindowPositionMain;
                WindowState = WindowState.Normal;
                Top = bounds.Top;
                Left = bounds.Left;
                Width = bounds.Width;
                Height = bounds.Height;

                GridLength gl = Properties.Settings.Default.MainColLeftWidth;
                gl = columnleft.Width;

                //columnleft.Width = Properties.Settings.Default.MainColLeftWidth;

                GUIUtil.Instance.Hex = Properties.Settings.Default.Hex;
                GUIUtil.Instance.UseAliases = Properties.Settings.Default.UseAliases;
            }
            catch
            { MessageBox.Show("problem retrieving stored settings"); }

            Closing += MainWindow_Closing;   // add handler for Closing event, to save window state

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

        void MainWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            // if user has a named filter file loaded and it has changed, offer to save
            if ((filters.ChangedSinceSave) && (filters.Filename != null))
                if (MessageBox.Show("Save Filter?", "Save Filter to " + filters.Filename, MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                    if (filters.Filename != null) filters.SaveToDisk(filters.Filename);
                    else filters.SaveAsToDisk();

            // save current filter in autosave file
            filters.SaveToDisk("c:\\pviewer\\autosave.filterset");

            Properties.Settings.Default.WindowPositionMain = this.RestoreBounds;
            Properties.Settings.Default.MainColLeftWidth = columnleft.Width;

            Properties.Settings.Default.Hex = GUIUtil.Instance.Hex;
            Properties.Settings.Default.UseAliases = GUIUtil.Instance.UseAliases;
            Properties.Settings.Default.Save();
            foreach (Window w in Application.Current.Windows) if (w != this) w.Close();
        }

		private void ChoosePCAPFile(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			Nullable<bool> result;

			dlg.Multiselect = false;
			dlg.InitialDirectory = Properties.Settings.Default.LastDirectory;
            dlg.FileName = Properties.Settings.Default.LastFile;
			result = dlg.ShowDialog();

			if (result == true)
			{
                pkts.Clear();
                foreach (GList gl in grouplistlist.L) gl.L.Clear();

                Properties.Settings.Default.LastDirectory = dlg.InitialDirectory;
                Properties.Settings.Default.LastFile = dlg.FileName;
                LoadPCAPFile(dlg.FileName);
			}
		}
        private void LoadPCAPFile(string filename)
        {
            PcapFile pfh;
            FileStream fs;
            Packet pkt;
            ulong seqno;

            byte[] b = new byte[1000];

            pkts.Clear();
            foreach (GList gl in grouplistlist.L) gl.L.Clear();

            fs = new FileStream(filename, FileMode.Open);
            PacketFileName = filename;
            FileLoaded = true;

            pfh = new PcapFile(fs);

            seqno = 0;
            while (fs.Position < fs.Length)
            {
                pkt = new Packet(fs, pfh);
                pkt.SeqNo = seqno++;    // assign sequence number - this is done now so that excluded packets will get sequence numbers
                if (filters.Include(pkt)) pkts.Add(pkt);
            }

            foreach (Packet p in pkts)
                foreach (GList gl in grouplistlist.L)
                    if (gl.GroupPacket(p)) break;

            foreach (TCPG tg in ((TCPGList)(grouplistlist.L[2])).L)
            {
                tg.OPL1.CopyBytes(1000, b);
                tg.OPL2.CopyBytes(1000, b);
            }
            gllview.Refresh();

            fs.Close();
        }
        private void grouptree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {
            if (e.NewValue == null) return;

            if (e.NewValue.GetType() == typeof(Packet))
            {
                if (pview == null) pview = new PacketViewer();
                pview.Pkt = (Packet)(e.NewValue);

                if (!(pview.Visibility == System.Windows.Visibility.Visible)) pview.Show();
            }

            //BOOKMARK

            // IF IT IS A PACKET, OPEN PACKET VIEW WINDOW ON IT
        }

        public void RefreshViews()
        {
            foreach (GList glist in grouplistlist.L)
            {
                foreach (G g in glist.L)
                {
                    g.Lview.Refresh();
                }
                glist.Lview.Refresh();
            }
            gllview.Refresh();
        }

        private void ApplyFilterToView(object sender, RoutedEventArgs e)
        {
            foreach (GList glist in grouplistlist.L)
            {
                foreach (G g in glist.L)
                {
                    foreach (Packet p in g.L) p.FiltersPassed = filters.Include(p);
                    g.Lview.Refresh();
                }
                glist.Lview.Refresh();
            }
            filters.ChangedSinceApplied = false;
            gllview.Refresh();
        }
        private void ReloadFile(object sender, RoutedEventArgs e)
        {
            if (PacketFileName != null) LoadPCAPFile(PacketFileName);
            filters.ChangedSinceApplied = false;
        }
        private void filterset_save(object sender, RoutedEventArgs e)
        {
            filters.SaveToDisk(null);
        }
        private void filterset_load(object sender, RoutedEventArgs e)
        {
            filters.LoadFromDisk(null);
        }
        private void filterset_clear(object sender, RoutedEventArgs e)
        {
            filters.Filters.Clear();
            filters.Filters.Add(new FilterAddItem());
            filters.ChangedSinceApplied = filters.ChangedSinceApplied = false;
            filters.Filename = null;
        }
        private void filter_addfilter(object sender, RoutedEventArgs e)
        {
            filters.Filters.Insert(filters.Filters.Count-1,new Filter(filters));
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;
            return;
        }
        private void filter_moveup(object sender, RoutedEventArgs e)
        {
            Filter thisfilter = (Filter)(((Button)sender).DataContext);
            int i = thisfilter.Parent.Filters.IndexOf(thisfilter);
            if (i == 0) return; // do nothing if already first item
            thisfilter.Parent.Filters.Move(i, i - 1);
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;
            return;
        }
        private void filter_movedown(object sender, RoutedEventArgs e)
        {
            Filter thisfilter = (Filter)(((Button)sender).DataContext);
            int i = thisfilter.Parent.Filters.IndexOf(thisfilter);
            if (i == thisfilter.Parent.Filters.Count-2) return; // do nothing if already the last item
            thisfilter.Parent.Filters.Move(i, i + 1);
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;
            return;
        }
        private void filter_delete(object sender, RoutedEventArgs e)
        {
            Filter thisfilter = (Filter)(((Button)sender).DataContext);
            int i = thisfilter.Parent.Filters.IndexOf(thisfilter);
            thisfilter.Parent.Filters.RemoveAt(i);
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;
            return;
        }
        private void filteritem_addfilteritem(object sender, RoutedEventArgs e)
        {
            // FilterItems need parent property to find the Filter they belong to
            Filter parent = ((FilterItem)(((Button)sender).DataContext)).Parent;
            parent.filterlist.Insert(parent.filterlist.Count-1, new FilterItemIP4(parent));
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;

            return;
        }
        private void filteritem_delete(object sender, RoutedEventArgs e)
        {
            FilterItem thisfilteritem = (FilterItem)(((Button)sender).DataContext);
            Filter parent = ((FilterItem)(((Button)sender).DataContext)).Parent;
            int i = parent.filterlist.IndexOf(thisfilteritem);
            parent.filterlist.RemoveAt(i);
            filters.ChangedSinceApplied = filters.ChangedSinceSave = true;
            return;
        }

        public void inmcelleditending(object sender, DataGridCellEditEndingEventArgs e)
        // this is part of the ip4 name map logic but it needs to be in MainWindow class
        // because it is an event handler and the reference in the xaml needs to 
        // be to something in the object to which it belongs, in this case the
        // MainWindow instance
            
        // this handles the CellEditEnding event from the datagrid
        // by marking the "changed since saved" flag true
        {
            inm.inmchangedsincesavedtodisk = true;
        }

        public void mnmcelleditending(object sender, DataGridCellEditEndingEventArgs e)
        // this is part of the ip4 name map logic but it needs to be in MainWindow class
        // because it is an event handler and the reference in the xaml needs to 
        // be to something in the object to which it belongs, in this case the
        // MainWindow instance

        // this handles the CellEditEnding event from the datagrid
        // by marking the "changed since saved" flag true
        {
            mnm.mnmchangedsincesavedtodisk = true;
        }

        private void TextBox_KeyUp(object sender, KeyEventArgs e)
        {
            TextBox tBox = (TextBox)sender;
            DependencyProperty prop = TextBox.TextProperty;
            MultiBindingExpression binding = BindingOperations.GetMultiBindingExpression(tBox, prop);

            switch (e.Key)
            {
                case Key.Enter:
                    // try to update source property (via binding, so validation happens)
                    if (binding != null) binding.UpdateSource();
                    break;

                case Key.Escape:
                    // revert TextBox.Text to source property value
                    if (binding != null) binding.UpdateTarget();
                    break;

                default:
                    // validate and update error state indication (red highlight around box)
                    if (binding != null) binding.ValidateWithoutUpdate();
                    break;
            }

        }
        private void TextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            TextBox tBox = (TextBox)sender;
            tBox.SelectionStart = 0;
            tBox.SelectionLength = tBox.Text.Length;
        }

        private void IDM_Apply_Filter(object sender, RoutedEventArgs e)
        {

            // instantiate new Regex objects with the values from the filter textboxes
            // connect view filter to new regexs
            // refresh the view

        }
    }



}
