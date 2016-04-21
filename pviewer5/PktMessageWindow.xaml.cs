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

    public partial class PktMessageWindow : Window
    {
        public struct pktmsggroup
        {
            public Protocols prot;
            public DateTime time;
            public List<string> msgs;
        }

        public static ObservableCollection<pktmsggroup> Msgs = new ObservableCollection<pktmsggroup>();

        // window will show list as a datagrid (for sorting)
                    
        // buttons for
        //  close
        //  close and clear dictionary




        public PktMessageWindow()
        {
            InitializeComponent();
        }
    }








}
