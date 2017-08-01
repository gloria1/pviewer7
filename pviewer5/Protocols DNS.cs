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
using System.Text.RegularExpressions;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;



namespace pviewer5
{

    public class IPDNMap : INotifyPropertyChanged
    {
        public static IPDNMap Instance = null;
        public IPDNMap()
        {
            if (Instance != null) MessageBox.Show("Something is instantiating a second instance of IPDNMap, which should never happen.");
            else Instance = this;

            tableview = (ListCollectionView)CollectionViewSource.GetDefaultView(table);
            tableview.Filter = new Predicate<object>(IDMFilter);

        }


        // view model for mapping of IP addresses to domain names
        // needs to be non-static so that it can be part of an instance that
        // is referenced by the MainWindow instance so that the xaml can
        // reference it in a databinding



        //  BOOKMARK

        //      need:
        //      property for domain display info in tableitem


        public class idmtable : ObservableCollection<idmtable.idmtableitem>
        {

            public class idmtableitem : INotifyPropertyChanged
            {
                public IP4 addr { get; set; }
                public string name { get; set; } = null;
                public DateTime firstobsn { get; set; } = new DateTime(0);
                public DateTime lastobsn { get; set; } = new DateTime(0);
                public int numberobserved { get; set; } = 1;
                public uint addrvalue { get { return addr.A; } }
                public string idminfostring
                {
                    get
                    {
                        return name;
                    }
                }
                public bool IsVisible
                {
                    get
                    {
                        // returns true only if match on both filters
                        if (!Regex.IsMatch(name, IPDNMap.Instance.domainfilter)) return false;
                        return Regex.IsMatch(addr.ToString(false, false), IPDNMap.Instance.ipfilter);
                    }
                }

                public idmtableitem(IP4 a, string n, DateTime ts, int num)
                {
                    addr = a;
                    name = n;
                    firstobsn = lastobsn = ts;
                    numberobserved += num;
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

            // MergeItem will be called by DNSRR constructor whenever it encounters records of type:
            //     A  -  mapping of name to an IP4 address
            //     NS -  mapping of a nameserver name to an IP4 address
            //     (someday) AAAA - mapping name to IP6
            public void MergeItem(IP4 a, string n, DateTime ts, int num)
            {
                foreach (idmtableitem i in this)
                {
                    if ((a == i.addr) && (n == i.name))
                    {
                        // update firstobsn, lastobsn, numberobserved
                        if (i.lastobsn < ts) i.lastobsn = ts;
                        if (i.firstobsn > ts) i.firstobsn = ts;
                        i.numberobserved += num;

                        // move this item to top of list, following a most recently used concept
                        this.Move(this.IndexOf(i), 0);

                        return;
                    }
                }
                // if we reached this point, newitem does not match any in table, so add it as a new table item
                this.Insert(0, new idmtableitem(a, n, ts, 1));

            }


        }

        public idmtable table { get; set; } = new idmtable();

        public ListCollectionView tableview;
        private string _ipfilter = ".*";
        public string ipfilter { get { return _ipfilter; } set { _ipfilter = value; NotifyPropertyChanged(); } }
        private string _domainfilter = ".*";
        public string domainfilter { get { return _domainfilter; } set { _domainfilter = value; NotifyPropertyChanged(); } }
        public bool IDMFilter(object p)
        {
            return ((idmtable.idmtableitem)p).IsVisible;
        }


        // reference to datagrid this table is bound to
        public DataGrid dg = null;

        private string _idmfilename = null;
        public string idmfilename { get { return _idmfilename; } set { _idmfilename = value; NotifyPropertyChanged(); } }
        public bool idmchangedsincesavedtodisk = false;


        public static RoutedCommand idmdelrow = new RoutedCommand();
        public static RoutedCommand idmload = new RoutedCommand();
        public static RoutedCommand idmmerge = new RoutedCommand();
        public static RoutedCommand idmsave = new RoutedCommand();
        public static RoutedCommand idmsaveas = new RoutedCommand();

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public static void idmExecuteddelrow(object sender, ExecutedRoutedEventArgs e)
        {
            idmtable.idmtableitem q = (idmtable.idmtableitem)(Instance.dg.SelectedItem);

            IPDNMap inst = IPDNMap.Instance;


            Instance.table.Remove(q);
            Instance.idmchangedsincesavedtodisk = true;
            Instance.NotifyPropertyChanged();
        }
        public static void idmCanExecutedelrow(object sender, CanExecuteRoutedEventArgs e)
        {
            // only enable if more than one row in table
            // this is a hack - for some reason, if there is only one row in the table and it gets deleted
            // the datagrid is left in some bad state such that the next add operation causes a crash
            // i gave up trying to diagnose it, so my "workaround" is to prevent deletion if there is only one
            // row left
            e.CanExecute = (Instance.table.Count() > 1) && (Instance.dg.SelectedItem != null);
        }
        public static void idmExecutedsave(object sender, ExecutedRoutedEventArgs e)
        {
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            try
            {
                fs = new FileStream(Instance.idmfilename, FileMode.Open);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (idmtable.idmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.addr);
                    formatter.Serialize(fs, i.name);
                    formatter.Serialize(fs, i.firstobsn);
                    formatter.Serialize(fs, i.lastobsn);
                    formatter.Serialize(fs, i.numberobserved);
                }
                Instance.idmchangedsincesavedtodisk = false;
                fs.Close();
            }
            catch
            {
                MessageBox.Show("Failed to save file");
            }

        }
        public static void idmCanExecutesave(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (Instance.idmchangedsincesavedtodisk && (Instance.idmfilename != null));
        }
        public static void idmExecutedsaveas(object sender, ExecutedRoutedEventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.FileName = Instance.idmfilename;
            dlg.DefaultExt = ".IDmap";
            dlg.OverwritePrompt = true;

            if (dlg.ShowDialog() == true)
            {
                IPDNMap inst = Instance;
                Instance.idmfilename = dlg.FileName;
                fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (idmtable.idmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.addr);
                    formatter.Serialize(fs, i.name);
                    formatter.Serialize(fs, i.firstobsn);
                    formatter.Serialize(fs, i.lastobsn);
                    formatter.Serialize(fs, i.numberobserved);
                }
                Instance.idmchangedsincesavedtodisk = false;
                fs.Close();
            }

        }
        public static void idmCanExecutesaveas(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void idmExecutedload(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".IDmap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                IPDNMap inst = Instance;

                try
                {
                    // clear existing table entries
                    Instance.table.Clear();

                    Instance.idmfilename = dlg.FileName;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                        Instance.table.Add(new idmtable.idmtableitem((IP4)formatter.Deserialize(fs), (string)formatter.Deserialize(fs), (DateTime)formatter.Deserialize(fs), (int)formatter.Deserialize(fs)) );

                    Instance.idmchangedsincesavedtodisk = false;
                }
                catch
                {
                    MessageBox.Show("File not read");
                }
                finally
                {
                    fs.Close();
                }
            }

        }
        public static void idmCanExecuteload(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void idmExecutedmerge(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".IDmap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                IPDNMap inst = Instance;

                try
                {
                    // DO NOT clear existing table entriesa
                    // Instance.table.Clear();
                    // Instance.map.Clear();

                    // change the filename to null
                    Instance.idmfilename = null;
                    Instance.idmchangedsincesavedtodisk = true;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                    {
                        IPDNMap.Instance.table.MergeItem((IP4)formatter.Deserialize(fs), (string)formatter.Deserialize(fs), (DateTime)formatter.Deserialize(fs), (int)formatter.Deserialize(fs));
                    }
                }
                catch
                {
                    MessageBox.Show("File not read completely");
                }
                finally
                {
                    fs.Close();
                }
            }

        }
        public static void idmCanExecutemerge(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }





    }






    public class DNSRR : PVDisplayObject
    {
        public Packet mypkt;            // reference to packet that contains this RR, so we can access the name string data
        public uint PDataIndex;         // index into mypkt.PData of beginning of DNS header - the NAME and RDATA values are relative to beginning of DNS header

        public uint NAME { get; set; }    // index into DNS header of beginning of NAME
        public uint TYPE { get; set; }
        public uint CLASS { get; set; }
        // fields after this do not exist for "question" rr, but do exist for "answers"
        public uint TTL { get; set; }
        public uint RDLENGTH { get; set; }
        public uint RDATA1 { get; set; }    // index into DNS header of beginning of first field of RDATA (how to resolve depends on TYPE)
        public uint RDATA2 { get; set; }
        public uint RDATA3 { get; set; }
        public uint RDATA4 { get; set; }    // index into DNS header of beginning of first field of RDATA (how to resolve depends on TYPE)
        public uint RDATA5 { get; set; }
        public uint RDATA6 { get; set; }
        public uint RDATA7 { get; set; }    // index into DNS header of beginning of first field of RDATA (how to resolve depends on TYPE)
        
        public override string displayinfo
        {
            get
            {
                string r = base.displayinfo;
                r += "DNS RR, ";

                // class
                r += "Class ";
                switch (CLASS)
                {
                    case 1: r += "IN"; break;
                    case 0xfe: r += "None"; break;
                    case 0xff: r += "Any"; break;
                    default: r += "UNEXPECTED value = " + CLASS.ToString();  break;
                }
                // type
                r += ", Type ";
                switch (TYPE)
                {
                    case 1: r += "A " + ((IP4)RDATA1).ToString(); break;
                    case 2: r += "NS - auth. name svr - " + formnamestring(RDATA1); break;
                    case 3: r += "MD - OBSOLETE RR TYPE!!!!"; break;
                    case 4: r += "MF - OBSOLETE RR TYPE!!!!"; break;
                    case 5: r += "CNAME - canonical name for alias - " + formnamestring(RDATA1); break;
                    case 6: r += "SOA - start of zone of auth, name server - " + formnamestring(RDATA1);  break;
                    case 7: r += "MB - mailbox domain - " + formnamestring(RDATA1); break;
                    case 8: r += "MG - mail group member - " + formnamestring(RDATA1); break;
                    case 9: r += "MR - mail rename domain - " + formnamestring(RDATA1); break;
                    case 10: r += "NULL"; break;
                    case 11: r += "WKS - well known service - IP: " + ((IP4)RDATA1).ToString() + String.Format(" Protocol {0:X2}",RDATA2); break;
                    case 12: r += "PTR - domain name pointer" + formnamestring(RDATA1); break;
                    case 13: r += "HINFO - host information CPU: " + System.Text.Encoding.Default.GetString(mypkt.PData, (int)RDATA1 + 1, (int)(mypkt.PData[RDATA1]))
                                    + ", OS: " + System.Text.Encoding.Default.GetString(mypkt.PData, (int)RDATA2 + 1, (int)(mypkt.PData[RDATA2]));
                         break;
                    case 14: r += "MINFO - mailbox/maillist info: " + formnamestring(RDATA1) + ", " + formnamestring(RDATA2); break;
                    case 15: r += String.Format("MX, preference: {0:X2}, ", RDATA1) + formnamestring(RDATA2); break;
                    case 16: r += "TXT: " + System.Text.Encoding.Default.GetString(mypkt.PData, (int)RDATA1, (int)(RDLENGTH)); break;
                    case 28: r += String.Format("AAAA {0:X8} {1:X8} {2:X8} {3:X8}", RDATA1, RDATA2, RDATA3, RDATA4); break;
                }

                // ttl
                r += ", TTL " + TTL.ToString() + ", ";

                r += "Name = " + formnamestring(NAME);
                // rdata


                return r;
            }
        }
        
        public void Advanceposovername(byte[] d, ref uint pos)
        {
            while (true)        // this loop moves pos forward to byte after name field; names end with either a label of zero length or a pointer to elsewhere in the dns message
            {
                if ((d[pos] & 0xc0) == 0xc0)  // if this is a pointer, 
                {
                    pos += 2;   // adjust pos to byte after pointer,
                    break;      // and break out of loop
                }
                else                // else this is a regular label entry
                {
                    if (d[pos] == 0)  // if the label length is zero,
                    {
                        pos++;              // move pos to after the zero length label
                        break;              // and exit the loop
                    }
                    else pos += (uint)(d[pos] + 1);     // else this is a regular label so adjust pos to byte after this label
                }
            }

        }

        public string formnamestring(uint dnsindex)    // argument is index into dns record of start of domain name
        {
            uint pdi = dnsindex + PDataIndex;   // pdi is the index into PData of the byte we are looking at
            string d = "";
            uint t;
            
            if (mypkt.PData[pdi] == 0) return "<root>"; // if NAME just points to a terminator, it is the root

            while (mypkt.PData[pdi] != 0)
            {
                 t = mypkt.PData[pdi];
                 switch (t & 0xc0)
                 {
                     case 0:     // name particle of length t, at t+1
                         if (d.Length != 0) d += ".";    // if we are here, then there is a non-zero-length label to add to the domain name, so put in a dot separator
                         d += System.Text.Encoding.Default.GetString(mypkt.PData, (int)pdi + 1, (int)t);
                         pdi += (t + 1);
                         break;
                     case 0xc0:  // this is a pointer to somewhere else in the RR
                         pdi = (t & 0x3f) * 0x100 + (uint)mypkt.PData[pdi + 1] + PDataIndex;
                         break;
                     default:    // this should never happen
                         MessageBox.Show("Invalid compressed domain name particle in DNS RR");
                         break;
                  }
            }
            return d;
        }

        public DNSRR(Packet pkt, DNSRRList parent, ref uint pos, bool isquestion, uint dnsindex)    // if isquestion==true, process as a question entry (having only NAME, TYPE and CLASS fields)
                : base(parent)
        {
            mypkt = pkt;
            PDataIndex = dnsindex;

            NAME = pos - PDataIndex;

            Advanceposovername(pkt.PData, ref pos);

            TYPE = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;
            CLASS = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;

            if (isquestion) return;     // if this is a "question" record, there are no further fields

            TTL = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;
            RDLENGTH = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1]; pos += 2;

            switch (TYPE)
            {
                case 1:         // A - a host address
                    RDATA1 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    IPDNMap.Instance.table.MergeItem((IP4)RDATA1, formnamestring(NAME), mypkt.Time, 1);
                    break;
                case 2:         // NS - an authoritative name server
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 5:         // CNAME - the canonical name for an alias
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 6:         // SOA - start of zone of authority
                    RDATA1 = pos - PDataIndex;        // MNAME - name server that was the original or primary source of data for this zone
                    Advanceposovername(pkt.PData, ref pos);
                    RDATA2 = pos - PDataIndex;        // RNAME - mailbox of person responsible for this zone
                    Advanceposovername(pkt.PData, ref pos);
                    RDATA3 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // SERIAL - version number of the original copy of the zone
                    RDATA4 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // REFRESH - time (seconds) before zone should be refreshed
                    RDATA5 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // RETRY - time (seconds) before a failed refresh should be retried
                    RDATA6 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // EXPIRE - upper limit on time (seconds) before zone is no longer authoritative 
                    RDATA7 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // MINIMUM - TTL that should apply to any RR from this zone
                    break;
                case 7:         // MB - mailbox domain name
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 8:         // MG - mail group member
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 9:         // MR - mail rename domain name
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 0x0a:         // NULL - a null RR
                    pos += RDLENGTH;
                    break;
                case 0x0b:         // WKS - well known service description
                    RDATA1 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // ADDRESS - 32 bit internet address
                    RDATA2 = (uint)pkt.PData[pos]; pos++;  // PROTOCOL - 8 bit IP protocol number
                    RDATA3 = pos;    // bitmap - bit position corresponds to port number, bit set indicates protocol supported on that port
                    pos += RDLENGTH - 5;
                    break;
                case 0x0c:         // PTR - domain name pointer
                    RDATA1 = pos - PDataIndex; pos += RDLENGTH;
                    break;
                case 0x0d:         // HINFO - host information
                    RDATA1 = pos; pos += pkt.PData[pos];   // CPU - character string (first byte is length, no null terminator)
                    RDATA2 = pos; pos += pkt.PData[pos];   // OS - character string (first byte is length, no null terminator)
                    break;
                case 0x0e:         // MINFO - mailbox or mail list information
                    RDATA1 = pos - PDataIndex;
                    Advanceposovername(pkt.PData, ref pos);
                    RDATA2 = pos - PDataIndex;
                    Advanceposovername(pkt.PData, ref pos);
                    break;
                case 0x0f:         // MX - mail exchange
                    RDATA1 = (uint)pkt.PData[pos] * 0x100 + (uint)pkt.PData[pos + 1];   // the preference value for this mail exchange (lower is higher preference)
                    RDATA2 = pos - PDataIndex + 2;                                      // name of mail exchange
                    pos += RDLENGTH;
                    break;
                case 0x10:         // TXT - text strings
                    RDATA1 = pos; pos += RDLENGTH;    // character strings (can be > 1) where first byte is length and no null terminators
                    break;
                case 0x1c:          // AAAA - IPv6 address
                    RDATA1 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    RDATA2 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    RDATA3 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    RDATA4 = (uint)pkt.PData[pos] * 0x1000000 + (uint)pkt.PData[pos + 1] * 0x10000 + (uint)pkt.PData[pos + 2] * 0x100 + (uint)pkt.PData[pos + 3]; pos += 4;  // A - internet address (ipv4)
                    break;

                case 3:         // MD - a mail destination (OBSOLETE per rfc 1035)
                case 4:         // MF - a mail forwarder (obsolete per rfc 1035) 
                default:
                    MessageBox.Show("Unhandled DNS RR Type - why are we receiving this?");
                    break;
            }
        }
    }

    public class DNSRRList : PVDisplayObject
    {
        public DNSRRList(DNSH parent) : base(parent)
        {
            L = new ObservableCollection<PVDisplayObject>();
        }

        public override string displayinfo
        {
            get
            {
                return base.displayinfo + String.Format("DNS RR List {0:X4} Items", L.Count);
            }
        }
    }


    public class DNSH : H
    {
        // define the fields of the header itself
        public uint Len { get; set; }

        public uint ID { get; set; }
        public uint QR { get; set; }        // 0 is query, 1 is response
        public uint OpCode { get; set; }     // 0 = standard query (QUERY)
        // 1 = inverse query (IQUERY)
        // 2 = server status request (STATUS)
        // 3-15 reserved (per rfc 1035, maybe more defined in later rfcs?)
        public uint AA { get; set; }        // authoritative answer
        public uint TC { get; set; }        // truncation = 1 if this message was truncated
        public uint RD { get; set; }        // recursion desired - directs name server to pursue query recursively
        public uint RA { get; set; }        // recursion available
        public uint Z { get; set; }         // reserved per rfc 1035
        public uint RCode { get; set; }     // response codes:
        //  0 = no error
        //  1 = format error
        //  2 = server failure
        //  3 = name error
        //  4 = not implemented
        //  5 = refused
        //  6 = reserved per rfc 1035
        public uint QDCOUNT { get; set; }   // number of questions
        public uint ANCOUNT { get; set; }   // number of answers
        public uint NSCOUNT { get; set; }   // number of name server authority records
        public uint ARCOUNT { get; set; }   // number of additional records

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                string s = base.displayinfo; 
                s += String.Format("DNS header text {0:X4}, ", ID);
                if (QR == 0) s += "QR is query";
                else s += "QR is response";

                if (RCode != 0) s += ", RCode INDICATES ERROR OR FAILURE OF SOME KIND";

                return s;
            }
        }


        public DNSH(FileStream fs, PcapFile pfh, Packet pkt, uint i) : base(fs, pfh, pkt, i)
        {
            DNSRRList newlist;
            uint pdataindex;  // index into PData of start of this header - used to convert RDATA values, which are indexed relative to start of DNS header, into indices into PData
            H container = (H)pkt.L[pkt.L.Count() - 1];     // containing header
            pdataindex = (uint)container.payloadindex;
            Len = (uint)container.payloadlen;

            // if not enough data remaining, return without reading anything 
            // note that we have not added the header to the packet's header list yet, so we are not leaving an invalid header in the packet
            if ((pkt.Len - i) < Len) return;

            ID = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            QR = ((uint)pkt.PData[i] & 0x80) / 0x80;
            OpCode = ((uint)pkt.PData[i] & 0x78) / 0x08;
            AA = ((uint)pkt.PData[i] & 0x04) / 0x04;
            TC = ((uint)pkt.PData[i] & 0x02) / 0x02;
            RD = ((uint)pkt.PData[i++] & 0x01);
            RA = ((uint)pkt.PData[i] & 0x80) / 0x80;
            Z = ((uint)pkt.PData[i] & 0x70) / 0x10;
            RCode = ((uint)pkt.PData[i++] & 0x000f);

            QDCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            ANCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            NSCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];
            ARCOUNT = (uint)pkt.PData[i++] * 0x100 + (uint)pkt.PData[i++];

            L = new ObservableCollection<PVDisplayObject>();    // L is list of DNSRRLists
            newlist = new DNSRRList(this);
            L.Add(newlist);    // add empty list to contain the questions
            for (int ii = 0; ii < QDCOUNT; ii++) L[0].L.Add(new DNSRR(pkt, newlist, ref i, true, pdataindex));

            newlist = new DNSRRList(this);
            L.Add(newlist);     // add empty list to contain the answers
            for (int ii = 0; ii < ANCOUNT; ii++) L[1].L.Add(new DNSRR(pkt, newlist, ref i, false, pdataindex));

            newlist = new DNSRRList(this);
            L.Add(newlist);   // add empty list to contain nameserver RRs
            for (int ii = 0; ii < NSCOUNT; ii++) L[2].L.Add(new DNSRR(pkt, newlist, ref i, false, pdataindex));

            newlist = new DNSRRList(this);
            L.Add(newlist);   // add empty list to contain additional RR's
            for (int ii = 0; ii < ARCOUNT; ii++) L[3].L.Add(new DNSRR(pkt, newlist, ref i, false, pdataindex));

            if (i != pkt.Len) MessageBox.Show("Did Not Read DNS record properly?  i != pkt.Len");

            // set generic header properties
            headerprot = Protocols.DNS;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.DNS;

            // add header to packet's header list
            pkt.L.Add(this);
        }

    }


    public class DNSG : G
    {
        // define properties of a specific group here
        public uint LocalPort;  // the port that is not 0x35, whether it be sender or receiver (the ID may be enough to uniquely identify the group, but making the local port part of the key as well can't hurt (can it?)
        public uint ID;

        // define a property that will be used by the xaml data templates for the one-line display of this header in the tree
        public override string displayinfo
        {
            get
            {
                string s = base.displayinfo;
                s += "DNS Group text, Question Name ";
                
                foreach (H h in L[0].L)
                    if (h.headerprot == Protocols.DNS)
                    {
                        DNSRR rr = (DNSRR)(((DNSH)h).L[0].L[0]);
                        s += rr.formnamestring(rr.NAME);
                        break;
                    }

                return s;
            }
        }

        public DNSG(Packet pkt, GList parent)
            : base(pkt, parent)
        {

            // note: base class constructor is called first (due to : base(pkt) above)

            // set group properties here
            ID = 0;
            Type = GTypes.DNS;

            foreach (H h in pkt.L)
                if (h.headerprot == Protocols.DNS)
                {
                    ID = ((DNSH)h).ID;
                    break;
                }

            if (pkt.SrcPort != 0x35) LocalPort = pkt.SrcPort;
            else LocalPort = pkt.DestPort;
        }

        public override bool Belongs(Packet pkt, H h)        // returns true if pkt belongs to group
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this save this function from having to search for the protocol header in pkt.phlist each time it is called

            // rules for membership in an DNS packet group:
            //      packet has DNS protocol present
            //      AND SrcPort matches
            //      AND ID matches

            // can assume GList.CanBelong has returned true

            DNSH dnsh = (DNSH)h;

            // can  assume CanBelongToThisType has returned true

            return ((dnsh.ID == ID) && ((pkt.SrcPort == LocalPort) || (pkt.DestPort == LocalPort)));

            // also set Complete = true if this packet completes group
            // not sure what the conditions are for a DNS group to be complete - have to look it up
        }

    }

    public class DNSGList : GList       // generic DNS of a packet group class
    {
        // declare and initialize headerselector for this class of GList
        public override Protocols headerselector { get; set; }


        public DNSGList(string n, PVDisplayObject parent) : base(n, parent)
        {
            // set headerselector to protocol header that G.GroupPacket should extract
            Type = GTypes.DNS ;
            headerselector = Protocols.DNS;
        }


        public override bool CanBelong(Packet pkt, H h)        // returns true if packet can belong to a group of this type
        {
            // h argument: the GList.GroupPacket function can pass in a reference to a relevant protocol header, so CanBelong does not have to search the header list every time it is called
            return (h != null);     // any packet with a DNS header can belong to a DNS group
        }
        public override G StartNewGroup(Packet pkt, H h)      // starts a new group if this packet can be the basis for a new group of this type
        {
            // h argument is for utility - GList.GroupPacket function will pass in a reference to the packet header matching the protocol specified in the GList - this saves this function from having to search for the protocol header in pkt.phlist each time it is called

            if (h != null) return new DNSG(pkt, this);     // any packet with a DNS header can start a DNS group
            else return null;       // return null if cannot start a group with this packet
        }
    }

}