using System;
using System.Collections.Generic;
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
using System.Windows.Shapes;

namespace pviewer5
{
    /// <summary>
    /// Interaction logic for StreamViewer.xaml
    /// </summary>
    public partial class StreamViewer : Window
    {
        public StreamViewer(byte[] streamdata, ulong bytestoshow)
        {
            InitializeComponent();

            // try to restore window position - see "Programing WPF Second Edition" page 321
            try
            {
                Rect bounds = Properties.Settings.Default.WindowPositionStreamViewer;
                this.Top = bounds.Top;
                this.Left = bounds.Left;
                this.Width = bounds.Width;
                this.Height = bounds.Height;
            }
            catch
            {  }

            Closing += PacketViewerWindow_Closing;   // add handler for Closing event, to save window state

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

            Packet testpkt = new Packet();
            testpkt.PData = new byte[64] {0x02, 0x05, 0x03, 0x04, 0x06, 0x0a, 0x0f, 0x0e, 0x03, 0x05, 0x34, 0x58, 0x89, 0xff, 0xfe, 0x02,
                0x02, 0x05, 0x03, 0x04, 0x06, 0x0a, 0x0f, 0x0e, 0x03, 0x05, 0x34, 0x58, 0x89, 0xff, 0xfe, 0x02,
                0x02, 0x05, 0x03, 0x04, 0x06, 0x0a, 0x0f, 0x0e, 0x03, 0x05, 0x34, 0x58, 0x89, 0xff, 0xfe, 0x02,
                0x02, 0x05, 0x03, 0x04, 0x06, 0x0a, 0x0f, 0x0e, 0x03, 0x05, 0x34, 0x58, 0x89, 0xff, 0xfe, 0x02};

            para.Inlines.Add(RenderLine(testpkt, 0, 6, 16, 0, 0));
            para.Inlines.Add(RenderLine(testpkt, 0, 16, 16, 0, 0));


            // packet metadata in brief form
            // packet headers in one line fomr
            // check boxes next to packet headers to highlight their data



        
        }

        void PacketViewerWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            Properties.Settings.Default.WindowPositionStreamViewer = this.RestoreBounds;
            Properties.Settings.Default.Save();
        }

        private void closebutton_Click(object sender, RoutedEventArgs e)
        {
            Close();
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

        public TextBlock RenderLine(Packet pkt, uint offset, uint datalen, uint linelen, uint firsttohighlight, uint lasttohighlight)
            // pkt - Packet containing source data
            // offset - offset in packet of first byte
            // datalen - length of valid data in Data
            // linelen - lenght of display line in bytes
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


    }
}
