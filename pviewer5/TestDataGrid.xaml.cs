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
    /// <summary>
    /// Interaction logic for TestDataGrid.xaml
    /// </summary>
    /// 


    public class tdgitem : INotifyPropertyChanged
    {
        public string timestamp { get; set; }
        public string ip { get; set; }
        public string proto { get; set; }
        public string grouptype {get; set;}
        public tdgitemlist parent { get; set; }
       
        public tdgitem(string t, string i, string p, string g, tdgitemlist par)
        {
            timestamp = t;
            ip = i;
            proto = p;
            grouptype = g;
            parent = par;
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

    public class tdgitemlist : ObservableCollection<tdgitem>
    {
        public tdgitemlist()
        {
        }
    }

    public class tdgviewitem : INotifyPropertyChanged
    {
        public tdgitem item { get; set; }
        public string grouped_ip { get; set; }
        public string grouped_proto { get; set; }
        public string grouped_grouptype { get; set; }

        public tdgviewitem(tdgitem i)
        {
            item = i;
            grouped_ip = null;
            grouped_proto = null;
            grouped_grouptype = null;
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
        public tdgitemlist l;
        public ObservableCollection<tdgviewitem> vl { get; set; }
        public CollectionView view;

        public TestDataGrid()
        {
            l = new tdgitemlist();
            l.Add(new tdgitem("001", "192.168.11.222", "arp", "arp", l));
            l.Add(new tdgitem("002", "192.168.11.223", "arp", "arp", l));
            l.Add(new tdgitem("003", "192.168.11.224", "arp", "arp", l));
            l.Add(new tdgitem("004", "192.168.11.222", "dns", "http", l));
            l.Add(new tdgitem("005", "192.168.11.223", "tcp", "tcp", l));
            l.Add(new tdgitem("006", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("007", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("008", "192.168.11.224", "arp", "arp", l));
            l.Add(new tdgitem("009", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("010", "192.168.11.223", "arp", "arp", l));
            l.Add(new tdgitem("011", "192.168.11.223", "arp", "arp", l));
            l.Add(new tdgitem("012", "192.168.11.225", "arp", "arp", l));
            l.Add(new tdgitem("013", "192.168.11.226", "arp", "arp", l));
            l.Add(new tdgitem("014", "192.168.11.222", "arp", "arp", l));
            l.Add(new tdgitem("015", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("016", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("017", "192.168.11.222", "tcp", "http", l));
            l.Add(new tdgitem("018", "192.168.11.222", "tcp", "http", l));


            vl = new ObservableCollection<tdgviewitem>();
            foreach (tdgitem t in l) vl.Add(new tdgviewitem(t));

            view = (ListCollectionView)CollectionViewSource.GetDefaultView(vl);

            InitializeComponent();

            tdg.DataContext = this;

        }
    }
}
