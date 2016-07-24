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

    // next steps:
    //  3) enable checkbox change logic
    //          should IsChecked setter just update firstheadershown, then let that setter cause re-draw of data?
    //          or should 
    //  4) enable highlighting of header data based on selection, or color coding of headers
    // set up code to handle selection change - put highlight on desired section of packet data
    // set up code in setters for FirstHeaderShown or SelectedHeader
    // set up code to handle SelectionChanged event

    /* OBJECTS, PROPERTlIES AND EVENT FLOW

        general design pattern:
            define class structure that corresponds to objects in the gui
            populate the objects with 
                properties with copies of the underlying data (actually references to it)
                properties that correspond to ui state, e.g., check box checked or selecteditem
            databind the xaml to these objects and make sure they implement INotifyPropertyChanged
            handle user input via property setter functions that get triggered when user changes something in the ui
            handle downstream effects of ui actions with property setters that include NotifyPropertyChanged to update gui
    */



    public partial class PacketViewer : Window, INotifyPropertyChanged
    // window that contains the packet view
    {
        // copy of underlying data   
        private Packet _pkt;
        public Packet Pkt
        {                    
            get { return _pkt; }
            set
            {
                _pkt = value;
                // populate HdrList
                if (value != null)
                {
                    int i = 0;
                    HdrList.Clear();
                    foreach (H h in value.L)
                    {
                        switch (h.headerprot)
                        {
                            case Protocols.DNS:
                                HdrList.Add(new PVHdrItemDNS(this, (DNSH)h, i >= FirstHdrShown));
                                break;
                            default:
                                HdrList.Add(new PVHdrItem(this, h, i >= FirstHdrShown));
                                break;
                        }
                        i++;
                    }
                }

                // cause Lines to be populated
                RenderPacketData();
            }
        }

        // backing objects for gui elements
        private ObservableCollection<PVHdrItem> _hdrlist;
        public ObservableCollection<PVHdrItem> HdrList        // list of header items - databound to xaml
        {
            get { return _hdrlist; }
            set
            {
                _hdrlist = value;
                // notify property changed
            }
        }

        // state variables for the view
        private int _firsthdrshown;
        public int FirstHdrShown                        // index of first header shown in data area - kept in sync with check boxes
                                                        // can be > lenght of Pkt.phlist, DataView will bounds-check this against the number of headers in the current packet
                                                        // this is a property of the PacketViewer window, not the list, because this 
                                                        // value should persist when the packet to be displayed changes and the old list
                                                        // is destroyed
        {
            get { return _firsthdrshown; }
            set
            {
                // check if value is change from current, skip logic below if no change
                if (value != _firsthdrshown)
                {
                    //      bounds check - constrain to be between 0 and hdrlist.count - if equal to count it means no headers will be shown
                    if (value < 0) _firsthdrshown = 0;
                    else if (value > HdrList.Count) _firsthdrshown = HdrList.Count;
                    else _firsthdrshown = value;

                    // if this box not already checked, then check it - setter for ischecked will cause all headers below to be checked as well
                    if (value < HdrList.Count) if (HdrList[value].IsChecked == false) HdrList[value].IsChecked = true;
                    // else if box above checked, uncheck it - setter for ischecked will cause all headers above to be unchecked as well
                    else if (value > 0) if (HdrList[value - 1].IsChecked == true) HdrList[value - 1].IsChecked = false;
                    // call RenderPacketData to update data view
                    RenderPacketData();
                }
            }
        }
        private int _selectedhdr;
        public int SelectedHdr                          // index of selected header - determines which header's data is highlighted
                                                        // can be -1 if no header selected
                                                        // can be > number of headers in current packet, because a higher header number was selected in the previous packet shown
                                                        // users of SelectedHdr must bounds-check it before indexing the header list
                                                        // similar to FirstHdrShown, this is a property of the window because it should persist when the packet changes
        {
            get { return _selectedhdr; }
            set
            {
                _selectedhdr = value;
                NotifyPropertyChanged();
                RenderPacketData();
                // update selecteditem property of hdrlist in xaml
                // how will dataview be triggered to update?  do i need to 
            }
        }
        
        // implement INotifyPropertyChanged interface
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public PacketViewer()
        // constructor - sets up empty packetviewer, with Pkt=null
        // restore window position
        {
            InitializeComponent();
            Pkt = null;
            HdrList = new ObservableCollection<PVHdrItem>();
            SelectedHdr = -1;
            grid.DataContext = this;

            // try to restore window position - see "Programing WPF Second Edition" page 321
            try
            {
                Rect bounds = Properties.Settings.Default.WindowPositionPacketViewer;
                WindowState = WindowState.Normal;
                Top = bounds.Top;
                Left = bounds.Left;
                Width = bounds.Width;
                Height = bounds.Height;
            }
            catch
            { }

            Closing += PacketViewerWindow_Closing;   // add handler for Closing event, to save window state
        }

        void PacketViewerWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        // saves window position
        {
            Properties.Settings.Default.WindowPositionPacketViewer = this.RestoreBounds;
            Properties.Settings.Default.Save();
        }

        public Run NewRun(string s, FontWeight fw)
        {
            Run ru = new Run(s);
            ru.FontWeight = fw;
            return ru;
        }

        public TextBlock RenderLine(int offset, int datalen, int linelen, int firsttohighlight, int firstafterhighlight)
        // creates one line of data view for packet, returns a TextBlock to be added to xamlparagraph
        // pkt - Packet containing source data
        // offset - offset in packet of first byte
        // datalen - length of valid data to display
        // linelen - length of display line in bytes
        // firsttohighlight, lasttohighlight - first and last bytes to be highglighted in bold
        // Data - byte array with packet data

        {
            string s = null;
            byte c;
            TextBlock tb = new TextBlock();
            Span sp = new Span();
            Run ru = new Run();
            int i;
            int drawlen = (datalen < linelen)? datalen :linelen;
            FontWeight fw;
      


            sp.Inlines.Add(String.Format("{0:X8} | ", offset));

            i = offset;
            fw = ((i >= firsttohighlight) && (i < firstafterhighlight)) ? FontWeights.Bold : FontWeights.Normal;

            while ((i - offset) < linelen)
            {
                if ((i - offset) < datalen)
                {
                    s = s + String.Format("{0:X2} ", Pkt.PData[i]);
                }
                else s = s + "   ";

                if ((i % 8) == 7) s = s + "  ";

                i++;

                if ((i == firsttohighlight) || (i == firstafterhighlight) || ((i - offset) == linelen))
                {
                    sp.Inlines.Add(NewRun(s, fw));
                    s = null;
                    fw = ((i >= firsttohighlight) && (i < firstafterhighlight)) ? FontWeights.Bold : FontWeights.Normal;
                }
            }

            sp.Inlines.Add(" | ");

            i = offset;
            fw = ((i >= firsttohighlight) && (i < firstafterhighlight)) ? FontWeights.Bold : FontWeights.Normal;

            while ((i - offset) < linelen)
            {
                if ((i - offset) < datalen)
                {
                    c = Pkt.PData[i];
                    if ((c >= 0x20) && (c < 0x7e)) s = s + (char)c;
                    else s = s + ".";
                }
                else s = s + " ";
                if ((i % 8) == 7) s = s + " ";

                i++;

                if ((i == firsttohighlight) || (i == firstafterhighlight) || ((i - offset) == linelen))
                {
                    sp.Inlines.Add(NewRun(s, fw));
                    s = null;
                    fw = ((i >= firsttohighlight) && (i < firstafterhighlight)) ? FontWeights.Bold : FontWeights.Normal;
                }
            }
 
            tb.Inlines.Add(sp);
            tb.TextWrapping = TextWrapping.NoWrap;
            
            return tb;
        }


        public void RenderPacketData()
        // updates xamlparagraph
        // function to be called when the data to be displayed changes, i.e.
        // when a new packet is shown, or
        // when the header check boxes change
        {
            int lastheaderhidden, i;
            int datainline; 
            int firsttohighlight, firstafterhighlight;

            if (Pkt == null) return;

            xamlparagraph.Inlines.Clear();

            i = 0;
            if (FirstHdrShown > 0)
            {
                lastheaderhidden = (FirstHdrShown < Pkt.L.Count()) ? (FirstHdrShown - 1) : (Pkt.L.Count() - 1);
                i = (int)((H)(Pkt.L[lastheaderhidden])).payloadindex;
            }
            
            firsttohighlight = firstafterhighlight = 0;  // default is to highlight nothing
            if ((SelectedHdr >= 0) && (SelectedHdr < Pkt.L.Count()))    // bounds check that SelectedHdr is a valid value for this packet, which it may not be if (a) no header has been selected yet or (b) for a previous packet it was a higher value than the number of headers in this packet
            {
                if (SelectedHdr > 0) firsttohighlight = (int)((H)Pkt.L[SelectedHdr - 1]).payloadindex;
                firstafterhighlight = (int)((H)Pkt.L[SelectedHdr]).payloadindex;
            }
            
            while (i < Pkt.PData.Length)
            {
                datainline = 16;
                if (Pkt.Len - i < 16) datainline = (int)Pkt.Len - i;
                xamlparagraph.Inlines.Add(RenderLine(i, datainline, 16, firsttohighlight, firstafterhighlight));
                i += 16;
            }

            // appears that object hierarchy is
            //      FlowDocumentScrollViewer.Document is the document in the viewer
            //          FlowDocumentScrollViewer.Document.Blocks is the list of blocks in the document
            //              Paragraph is one of the types of blocks
            //                  Paragraph.Inlines is the list of inline elements
            //                      Paragraph.Inlines list can include TextBlocks, Spans and Runs
            //                          TextBlock.Inlines can include Spans and Runs
            //                              Spans consist of Runs
            //    e.g.
            //          para.Inlines.Add(tblk1);
            //          tblk1.Inlines.Add(span1);
            //          para.Inlines.Add(new LineBreak());
            //          tblk1.TextWrapping = TextWrapping.NoWrap;

        }


    }


    /*
    events
        pviewer window created - write the constructor to create an empty PAcketViewer, with Pkt=null
        user sets Pkt property - write a setter method for Pkt
        check box check/uncheck - write a setter method for PVHdrItem.IsChecked
        selected item changes - write a setter method for SelectedHdr (the event handler for the GUI ListView will set SelectedHdr to trigger the update)

    methods
        populate HdrList - load it up based on Pkt
        populate DataView

    */

    public class PVHdrItem : INotifyPropertyChanged
    {
        public virtual H Hdr { get; set; }                  // the packet header being displayed
        private bool _ischecked;
        public bool IsChecked         // state of the checkbox
        {
            get { return _ischecked; }
            set
                // check/uncheck boxes below/above as appropriate
                // make sure gui updates
                // also update FirstHdrShown
             {
                int thisindex;
                int listcount;

                _ischecked = value; NotifyPropertyChanged();

                if (Parent == null) return;

                thisindex = Parent.HdrList.IndexOf(this);
                if (thisindex == -1) return; // if we are still in the constructor and this item has not been placed into a list yet, skip the logic below

                listcount = Parent.HdrList.Count();

                //test
                // IF EVENT WAS A CHECK, MAKE SURE NEXT ITEM BELOW IS CHECKED AS WELL (THIS WILL CASCADE DOWN THE LIST THROUGH REPEATED CALLS OF THIS SETTER)
                // WE ASSUME THE LIST OF CHECK BOXES IS IN A VALID STATE ALREADY, I.E., 0 OR MORE UNCHECKED ITEMS FOLLOWED BY 0 O MORE CHECKED ITEMS
                // set FirstHeaderShown = min(FirstHeaderShown, thisindex)
                if (value == true)
                {
                    if (thisindex < Parent.FirstHdrShown) Parent.FirstHdrShown = thisindex;
                    if (thisindex < listcount - 1)
                        if (Parent.HdrList[thisindex + 1].IsChecked == false)
                            Parent.HdrList[thisindex + 1].IsChecked = true;
                }
                // IF EVENT WAS AN UNCHECK, MAKE SURE ALL ABOVE ARE UNCHECKED
                else
                {
                    if ((thisindex + 1) > Parent.FirstHdrShown) Parent.FirstHdrShown = thisindex + 1;
                    if (thisindex > 0)
                        if (Parent.HdrList[thisindex - 1].IsChecked == true) Parent.HdrList[thisindex - 1].IsChecked = false;
                }
            }
        }
        public PacketViewer Parent;    // the PacketViewer window that owns this - needed to update other items in response to checkbox events

        // implement interface
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public PVHdrItem()
        // empty constructor so sub-class constructor can work
        { }

        public PVHdrItem(PacketViewer parent, H hdr, bool ischecked)
        // constructor
        {
            Hdr = hdr;
            Parent = parent;
            IsChecked = ischecked;
        }
    }

    public class PVHdrItemDNS : PVHdrItem, INotifyPropertyChanged
    {
        public DNSH Hdr { get; set; }

        public PVHdrItemDNS(PacketViewer parent, DNSH h, bool ischecked)
        {
            Hdr = h;
            Parent = parent;
            IsChecked = ischecked;
        }
    }


}



/* OLDER VERSION OF CODE BELOW, KEEP FOR REFERENCE

    public class PVHdrItem : INotifyPropertyChanged
    {
        private bool _ischecked;
        public bool IsChecked
        {
            get { return _ischecked; }
            set
            {
                int thisindex; 
                int listcount;

                _ischecked = value; NotifyPropertyChanged();

                if (Parent == null) return;

                thisindex = Parent.HdrItems.IndexOf(this);
                if (thisindex == -1) return; // if we are still in teh constructor and this item has not been placed into a list yet, skip the logic below

                listcount = Parent.HdrItems.Count();

                //test
                // IF EVENT WAS A CHECK, MAKE SURE NEXT ITEM BELOW IS CHECKED AS WELL (THIS WILL CASCADE DOWN THE LIST THROUGH REPEATED CALLS OF THIS SETTER)
                // WE ASSUME THE LIST OF CHECK BOXES IS IN A VALID STATE ALREADY, I.E., 0 OR MORE UNCHECKED ITEMS FOLLOWED BY 0 O MORE CHECKED ITEMS
                // set FirstHeaderShown = min(FirstHeaderShown, thisindex)
                if (value == true)
                {
                    if (thisindex < listcount-1)
                        if (Parent.HdrItems[thisindex+1].IsChecked == false)
                            Parent.HdrItems[thisindex+1].IsChecked = true;
                    Parent.Parent.FirstHeaderShown = (thisindex < Parent.Parent.FirstHeaderShown) ? thisindex : Parent.Parent.FirstHeaderShown;
                }
                // IF EVENT WAS AN UNCHECK, MAKE SURE ALL ABOVE ARE UNCHECKED
                else
                {
                    if (thisindex > 0)
                        if (Parent.HdrItems[thisindex-1].IsChecked == true) Parent.HdrItems[thisindex-1].IsChecked = false;
                    Parent.Parent.FirstHeaderShown = (thisindex > Parent.Parent.FirstHeaderShown) ? thisindex : Parent.Parent.FirstHeaderShown;
                }
            }
        }
        public virtual H Hdr { get; set; }
        public PVHdrItemList Parent { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public PVHdrItem()
        { }
        
        public PVHdrItem(H h, bool ischecked, PVHdrItemList parent)
        {
            Hdr = h;
            Parent = parent;
            IsChecked = ischecked;
        }
    }

    public class PVHdrItemDNS : PVHdrItem
    {
        public DNSH Hdr { get; set; }

        public PVHdrItemDNS(DNSH h, bool ischecked, PVHdrItemList parent)
        {
            Hdr = h;
            Parent = parent;
            IsChecked = ischecked;
        }
    }
    
    public class PVHdrItemList : INotifyPropertyChanged
        // the list of checkboxes is restricted to only be in a state where all checkboxes before FirstHeaderShown are unchecked, and all at and beyond FirstHeaderSHown are checked
        // property setter for the checkboxes in the PVHdrItem code will enforce this
        // if FirstHeaderShown >= HdrItems.Count, then all boxes are unchecked
    {
        private ObservableCollection<PVHdrItem> _hdritems;
        public ObservableCollection<PVHdrItem> HdrItems { get { return _hdritems; } set { _hdritems = value; NotifyPropertyChanged("HdrItems"); } }
        public PacketViewer Parent { get; set; }

        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public PVHdrItemList(Packet pkt, PacketViewer parent)
        {
            HdrItems = new ObservableCollection<PVHdrItem>();
            Parent = parent;

            if (pkt != null) {
                int i = 0;
                foreach (H h in pkt.phlist)
                {
                    switch (h.headerprot)
                    {
                        case Protocols.DNS:
                            HdrItems.Add(new PVHdrItemDNS((DNSH)h, i>=parent.FirstHeaderShown, this));
                            break;
                        default:
                            HdrItems.Add(new PVHdrItem(h, i>=parent.FirstHeaderShown, this));
                            break;
                    }
                    i++;
                }
            }
        }
    }
    

        public void ShowPacket(Packet pkt)
            // function called when packet to be displayed changes
        {

            Pkt = pkt;

            // create new header list
            HdrList = new PVHdrItemList(Pkt, this);

            listlen = HdrItems.Count(); first = Parent.FirstHeaderShown; selected = Parent.SelectedHeader;

            // set first and selected - ensure they are not beyond the end of the list (though it can equal the list count, indicating that no items are checked
            Parent.FirstHeaderShown = (first < listlen) ? first : listlen;
            Parent.SelectedHeader = (selected < listlen) ? selected : listlen;

            RenderPacketData();
        }
        
        private void actionbutton_Click(object sender, RoutedEventArgs e)
        {
            Span newspan = new Span(new Run("new span text should be bold"));
            newspan.FontWeight = FontWeights.Bold;
            newspan.FontFamily = new FontFamily("Courier New");
            TextBlock newblock = new TextBlock();
            newblock.TextWrapping = TextWrapping.NoWrap;
            newblock.Inlines.Add(newspan);
            para.Inlines.Add(newblock);
            para.Inlines.Add(new LineBreak());

        }
        
    }
}

    */
