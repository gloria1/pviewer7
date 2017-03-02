﻿using System;
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
        public object group { get; set; }
        public Type grouptype { get { return group.GetType(); } }
        public ObservableCollection<tdgitem> parent { get; set; }

        public string grouped_ip { get; set; }
        public string grouped_proto { get; set; }
        public object grouped_group { get; set; }
        public Type grouped_grouptype { get; set; }

        public tdgitem(string t, string i, string p, object g, ObservableCollection<tdgitem> par)
        {
            timestamp = t;
            ip = i;
            proto = p;
            group = g;
            parent = par;
            switch (ip)
            {
                case "192.168.11.222":
                    grouped_ip = "OTHER";
                    break;
                case "192.168.11.224":
                    grouped_ip = "OTHER";
                    break;
                default:
                    grouped_ip = ip;
                    break;
            }
            grouped_proto = proto;
            grouped_group = group;
            grouped_grouptype = grouptype;
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


    public class tdggroupingaxis : INotifyPropertyChanged
    {
        public string propertyname { get; set; }
        public string displayname { get; set; }
        public bool ischecked { get; set; }
        public ObservableCollection<tdggroupingaxis> parent;

        public tdggroupingaxis(string pn, string dn, ObservableCollection<tdggroupingaxis> par)
        {
            propertyname = pn;
            displayname = dn;
            ischecked = true;
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




    public partial class TestDataGrid : Window
    {
        public ObservableCollection<tdgitem> vl { get; set; }
        public ListCollectionView view;

        public ObservableCollection<tdggroupingaxis> axes { get; set; }

        public string arpgroup1 = "arpgroup1";
        public string arpgroup2 = "arpgroup2";
        public int httpgroup1 = 1;
        public int httpgroup2 = 2;

        public TestDataGrid()
        {
            vl = new ObservableCollection<tdgitem>();
            axes = new ObservableCollection<tdggroupingaxis>();

            InitializeComponent();
            tdggrid.DataContext = this;

            vl.Add(new tdgitem("001", "192.168.11.222", "arp", arpgroup1,  vl));
            vl.Add(new tdgitem("002", "192.168.11.223", "arp", arpgroup1,  vl));
            vl.Add(new tdgitem("003", "192.168.11.224", "arp", arpgroup1,  vl));
            vl.Add(new tdgitem("004", "192.168.11.222", "dns", httpgroup1, vl));
            vl.Add(new tdgitem("005", "192.168.11.223", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("006", "192.168.11.222", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("007", "192.168.11.222", "tcp", httpgroup1, vl));
            vl.Add(new tdgitem("008", "192.168.11.224", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("009", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("010", "192.168.11.223", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("011", "192.168.11.223", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("012", "192.168.11.225", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("013", "192.168.11.226", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("014", "192.168.11.222", "arp", arpgroup2,  vl));
            vl.Add(new tdgitem("015", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("016", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("017", "192.168.11.222", "tcp", httpgroup2, vl));
            vl.Add(new tdgitem("018", "192.168.11.222", "tcp", httpgroup2, vl));

            axes.Add(new tdggroupingaxis("grouped_proto", "Protocol", axes));
            axes.Add(new tdggroupingaxis("grouped_ip", "IP Address", axes));
            axes.Add(new tdggroupingaxis("grouped_group", "Group", axes));


            // next line gets view on vl, not on tdg.Itemssource
            // at this point in execution, tdg.Itemssource is still null,
            // even though it must get set somewhere later on because the datagrid
            // does get populated correctly
            view = (ListCollectionView)CollectionViewSource.GetDefaultView(vl);

            SetGrouping();

        }

        void SetGrouping()
        {
            view.GroupDescriptions.Clear();
            foreach (tdggroupingaxis a in axes)
                if (a.ischecked)
                    view.GroupDescriptions.Add(new PropertyGroupDescription(a.propertyname));

            view.Refresh();

        }


        void tdgaxischeck_Click(object sender, RoutedEventArgs e)
        {
            CheckBox b = (CheckBox)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            SetGrouping();
        }

        void tdgaxisup_Click(object sender, RoutedEventArgs e)
        {
            Button b = (Button)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            ObservableCollection<tdggroupingaxis> mylist = i.parent;
            int pos = mylist.IndexOf(i);

            if (pos == 0) return;
            mylist.Move(pos, pos - 1);

            SetGrouping();

        }

        void tdgaxisdown_Click(object sender, RoutedEventArgs e)
        {
            Button b = (Button)sender;
            tdggroupingaxis i = (tdggroupingaxis)b.DataContext;

            ObservableCollection<tdggroupingaxis> mylist = i.parent;
            int pos = mylist.IndexOf(i);

            if (pos == mylist.Count()) return;
            mylist.Move(pos, pos + 1);

            SetGrouping();



        }

    }


}