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

    public class PVHdrItem
    {
        public bool Checked { get; set; }
        public H Hdr { get; set; }

        public string headerdisplayinfo { get { return Hdr.headerdisplayinfo; } }
    }


    public partial class PacketViewer : Window
    {

        public ObservableCollection<Packet> pktlist { get; set; }
        public ObservableCollection<PVHdrItem> hdritems {get; set;}

        public PacketViewer()
        {
            InitializeComponent();

            pktlist = new ObservableCollection<Packet>();
            hdritems = new ObservableCollection<PVHdrItem>();
            grid.DataContext = this;

            // try to restore window position - see "Programing WPF Second Edition" page 321
            try
            {
                Rect bounds = Properties.Settings.Default.WindowPositionPacketViewer;
                this.Top = bounds.Top;
                this.Left = bounds.Left;
                this.Width = bounds.Width;
                this.Height = bounds.Height;
            }
            catch
            {  }

            Closing += PacketViewerWindow_Closing;   // add handler for Closing event, to save window state


        
        }

        void PacketViewerWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Properties.Settings.Default.WindowPositionPacketViewer = this.RestoreBounds;
            Properties.Settings.Default.Save();
        }

        private void actionbutton_Click(object sender, RoutedEventArgs e)
        {
            Span newspan = new Span(new Run("new span text should be bold"));
            newspan.FontWeight=FontWeights.Bold;
            newspan.FontFamily = new FontFamily("Courier New");
            TextBlock newblock = new TextBlock();
            newblock.TextWrapping = TextWrapping.NoWrap;
            newblock.Inlines.Add(newspan);
            para.Inlines.Add(newblock);
            para.Inlines.Add(new LineBreak());

        }

        private void closebutton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        public TextBlock RenderLine(Packet pkt, uint offset, uint datalen, uint linelen, uint firsttohighlight, uint lasttohighlight)
            // pkt - Packet containing source data
            // offset - offset in packet of first byte
            // datalen - length of valid data to display
            // linelen - length of display line in bytes
            // firsttohighlight, lasttohighlight - first and last bytes to be highglighted in bold
            // Data - byte array with packet data

        {
            string s;
            byte c;
            TextBlock tb = new TextBlock();

            s = String.Format("{0:X8} | ", offset);

            for (int i = 0; i < linelen; i++)
            {
                if (i < datalen)
                {
                    s = s + String.Format("{0:X2} ", pkt.PData[offset + i]);
                }
                else s = s + "   ";

                if ((i % 8) == 7) s = s + "  ";
            }
            s += " | ";
            for (int i = 0; i < linelen; i++)
            {
                if (i < datalen)
                {
                    c = pkt.PData[offset + i];
                    if ((c >= 0x20) && (c < 0x7e)) s = s + (char)c;
                    else s = s + ".";
                }
                else s = s + " ";
                if ((i % 8) == 7) s = s + " ";

            }
            tb.Inlines.Add(new Span(new Run(s)));
            tb.TextWrapping = TextWrapping.NoWrap;



            // basic render is byte values, string
            // handle short array
            // add argument for line lenghth
            // add argument for offset label (and add label to result)
            // add arguments for formatting to apply to subsets of the data

            
            return tb;
        }

        public void ShowPacket(Packet pkt)
        {
            uint i;
            int ii;
            int countdifference;
            PVHdrItem newitem;
            uint datainline;

            pktlist.Clear();
            pktlist.Add(pkt);

            // add to or remove from hdritems, leaving Checked status unchanged for items that carry over
            countdifference = pkt.phlist.Count - hdritems.Count;
            while (countdifference > 0)
            {
                newitem = new PVHdrItem();
                newitem.Checked = true;
                hdritems.Add(newitem);
                countdifference--;
            }
            while (countdifference < 0)
            {
                hdritems.RemoveAt(hdritems.Count - 1);
                countdifference++;
            }

            // now copy in the headers from pkt
            for (ii = 0; ii < pkt.phlist.Count; ii++)
            {
                hdritems[ii].Hdr = new H();
                hdritems[ii].Hdr = pkt.phlist[ii];
            }

            CollectionViewSource.GetDefaultView(headerlist.ItemsSource).Refresh();

            para.Inlines.Clear();

            for (i = 0; i < pkt.PData.Length; i += 16)
            {
                datainline = 16;
                if (pkt.Len - i < 16) datainline = pkt.Len - i;
                para.Inlines.Add(RenderLine(pkt, i, datainline, 16, 0, 0));

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


            // packet metadata in brief form
            // packet headers in one line fomr
            // check boxes next to packet headers to highlight their data




        }

        private void Header_Vis_CheckBox_Click(object sender, RoutedEventArgs e)
        {

            // TECHNIQUE IS TO USE VISUALTREEHELPER TO GETPARENT UP TO THE STACKPANEL THAT CONTAINS THE WHOLE PACKET
            // THEN GET THE DATACONTEXT PROPERTY, WHICH IS THE PACKET IN QUESTION

            H h = (H)(((CheckBox)sender).DataContext);

            DependencyObject target = (DependencyObject)sender;
            do
            {
                target = VisualTreeHelper.GetParent(target);
            }
            while (target != null);
        }

        private void headertree_SelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
        {

        }

        private void headerlist_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

        }
    }
}
