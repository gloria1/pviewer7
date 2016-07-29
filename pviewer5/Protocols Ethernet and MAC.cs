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

    [Serializable]
    public struct MAC
    {
        public ulong A;

        public override bool Equals(object a)
        {
            if (a == DependencyProperty.UnsetValue) return false;
            else return ((MAC)a).A == A;
        }
        public override int GetHashCode() { return A.GetHashCode(); }
        public static implicit operator MAC(ulong i) { MAC r = new MAC(); r.A = i; return r; }
        public static MAC operator +(MAC a, MAC b) { MAC r = new MAC(); r.A = a.A + b.A; return r; }
        public static MAC operator *(MAC a, MAC b) { MAC r = new MAC(); r.A = a.A * b.A; return r; }
        public static MAC operator &(MAC a, MAC b) { MAC r = new MAC(); r.A = a.A & b.A; return r; }
        public static MAC operator |(MAC a, MAC b) { MAC r = new MAC(); r.A = a.A | b.A; return r; }
        public static bool operator ==(MAC a, MAC b) { return a.A == b.A; }
        public static bool operator !=(MAC a, MAC b) { return a.A != b.A; }
        public static bool operator <=(MAC a, MAC b) { return a.A <= b.A; }
        public static bool operator <(MAC a, MAC b) { return a.A < b.A; }
        public static bool operator >=(MAC a, MAC b) { return a.A >= b.A; }
        public static bool operator >(MAC a, MAC b) { return a.A > b.A; }

        public override string ToString() { return ToString(true); }

        public string ToString(bool usealiasesthistime)
        // if usealiasesthistime == true, then if global UseAliases is true, return the alias
        {
            if (usealiasesthistime && GUIUtil.Instance.UseAliases)
                if (MACAliasMap.Instance.table.IndexOf(A) != -1)
                    return MACAliasMap.Instance.table.Lookup(A);

            ulong[] b = new ulong[6];
            string s;

            b[0] = ((A & 0xff0000000000) / 0x10000000000);
            b[1] = ((A & 0xff00000000) / 0x100000000);
            b[2] = ((A & 0xff000000) / 0x1000000);
            b[3] = ((A & 0xff0000) / 0x10000);
            b[4] = ((A & 0xff00) / 0x100);
            b[5] = ((A & 0xff) / 0x1);

            s = String.Format("{0:x2}:{1:x2}:{2:x2}:{3:x2}:{4:x2}:{5:x2}", b[0], b[1], b[2], b[3], b[4], b[5]);

            return s;
        }

        public string ToStringAlts()
        // return strings of forms other than what would be returned by ToString
        //      if UseAliases, then numerical form based on Hex
        //      if !UseAliases, then alias if there is one
        {
            if (GUIUtil.Instance.UseAliases) return ToString(false);
            else if (MACAliasMap.Instance.table.IndexOf(A) != -1) return MACAliasMap.Instance.table.Lookup(A);
            else return "no alias";
        }

        public bool TryParse(string s)
        // tries to parse string into A
        // first tries to parse a simple number
        // if that fails, tries to parse as a numerical dot format address, respecting global Hex flag
        // if that fails, checks for match of an alias
        // if no match or any errors, returns false and does not assign value
        {
            // first try to parse as a raw MAC address
            string[] macbits = new string[6];
            string regexmac = "^([a-fA-F0-9]{0,2}[-:]){0,5}[a-fA-F0-9]{0,2}$";

            try
            {
                A = ulong.Parse(s, NumberStyles.HexNumber);
                return true;
            }
            // if could not parse as simple number
            catch (FormatException ex)
            {
                // try parsing as : notation
                if (Regex.IsMatch(s, regexmac))
                {
                    macbits = Regex.Split(s, "[:-]");
                    // resize array to 6 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
                    // split will produce array with number of elements equal to nmber of dots + 1
                    Array.Resize<string>(ref macbits, 6);

                    for (int i = 0; i < 6; i++) { macbits[i] = "0" + macbits[i]; }

                    try
                    {
                        A = ulong.Parse(macbits[0], NumberStyles.HexNumber) * 0x0000010000000000 +
                            ulong.Parse(macbits[1], NumberStyles.HexNumber) * 0x0000000100000000 +
                            ulong.Parse(macbits[2], NumberStyles.HexNumber) * 0x0000000001000000 +
                            ulong.Parse(macbits[3], NumberStyles.HexNumber) * 0x0000000000010000 +
                            ulong.Parse(macbits[4], NumberStyles.HexNumber) * 0x0000000000000100 +
                            ulong.Parse(macbits[5], NumberStyles.HexNumber) * 0x0000000000000001;
                        return true;
                    }
                    catch { }
                }
                // if we have gotten this far, s was not parsed as a simple number or dot notation number, so check if it is a valid alias
                foreach (MACAliasMap.mnmtable.mnmtableitem m in MACAliasMap.Instance.table)
                    if (s == m.alias)
                    {
                        A = m.MAC.A;
                        return true;
                    }

                // if we get to here, s could not be parsed in any valid way, so return false;
                return false;
            }

        }

    }




    public class MACAliasMap : INotifyPropertyChanged
    {
        public static MACAliasMap Instance = null;
        public MACAliasMap()
        {
            if (Instance != null) MessageBox.Show("Something is instantiating a second instance of MACAliasMap, which should never happen.");
            else Instance = this;
        }


        // view model for mapping of MAC values to aliases
        // needs to be non-static so that it can be part of an instance that
        // is referenced by the MainWindow instance so that the xaml can
        // reference it in a databinding

        public class mnmtable : ObservableCollection<mnmtable.mnmtableitem>
        {
            // backing model for MAC name map - it is a dictionary since we want to be able to look up by just indexing the map with an MAC address
            // this is private so there is no way anything outside this class can alter the dictionary  without updating the table
            // i.e., all external access to the map will be through the table
            private Dictionary<MAC, string> dict = new Dictionary<MAC, string>();

            public new void Add(mnmtableitem it)
            // return without doing anything if it is a duplicate of an mac already in table
            {
                if (IndexOf(it.MAC) == -1)
                {
                    it.parent = this;
                    base.Add(it);
                    dict.Add(it.MAC, it.alias);
                }
            }
            public new bool Remove(mnmtableitem it)
            {
                int ix = IndexOf(it.MAC);
                if (ix == -1) return false;
                else return RemoveAt(ix);
            }
            public string Lookup(MAC mac)
            {
                return dict[mac];
            }
            public int IndexOf(MAC mac)
            {
                for (int i = 0; i < this.Count(); i++) if (this[i].MAC == mac) return i;
                return -1;
            }
            public new bool RemoveAt(int i)
            {
                if ((i < 0) || (i >= this.Count())) return false;
                dict.Remove(this[i].MAC);
                base.RemoveAt(i);
                return true;
            }
            public new void Clear()
            {
                base.Clear();
                dict.Clear();
            }


            public class mnmtableitem : INotifyPropertyChanged
            {
                public mnmtable parent = null;
                private MAC _mac;
                public MAC MAC
                {
                    get { return _mac; }
                    set
                    {
                        // fail if this mac is a duplicate of one already in the dictionary 
                        // this should never happen
                        // gui validator logic should prevent it
                        if (parent != null)
                        {
                            if (parent.IndexOf(value) != -1)
                            {
                                MessageBox.Show("ATTEMPT TO CREATE DUPLICATE ADDRESS IN mac NAME MAP\nTHIS SHOULD NEVER HAPPEN\nGUI VALIDATION LOGIC SHOULD PREVENT THIS");
                                return;
                            }

                            // need to update dict to keep in sync - i think we need to delete old item and add a new one
                            string s = parent.Lookup(_mac);
                            parent.dict.Remove(_mac);
                            parent.dict.Add(value, s);
                            _mac = value;

                            // if this is part of the main gui viewmodel, update the dirty flag
                            if (parent == Instance.table) Instance.mnmchangedsincesavedtodisk = true;
                        }
                        NotifyPropertyChanged();        // notify the gui
                        GUIUtil.Instance.UseAliases = GUIUtil.Instance.UseAliases;    // this will trigger notification of any other gui items that use aliases
                    }
                }
                private string _alias;
                public string alias
                {
                    get { return _alias; }
                    set
                    {
                        _alias = value;

                        // update dict
                        if (parent != null) parent.dict[_mac] = value;
                        if (parent == Instance.table) Instance.mnmchangedsincesavedtodisk = true;

                        NotifyPropertyChanged();        // notify the gui
                        GUIUtil.Instance.UseAliases = GUIUtil.Instance.UseAliases;    // this will trigger notifications of any other gui items that use aliases
                    }
                }

                public mnmtableitem(MAC u, string s)
                {
                    _mac = u;
                    _alias = s;
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

        }

        public mnmtable table { get; set; } = new mnmtable();

        // reference to datagrid this table is bound to
        public DataGrid dg = null;

        private string _mnmfilename = null;
        public string mnmfilename { get { return _mnmfilename; } set { _mnmfilename = value; NotifyPropertyChanged(); } }
        public bool mnmchangedsincesavedtodisk = false;


        public static RoutedCommand mnmaddrow = new RoutedCommand();
        public static RoutedCommand mnmdelrow = new RoutedCommand();
        public static RoutedCommand mnmload = new RoutedCommand();
        public static RoutedCommand mnmappend = new RoutedCommand();
        public static RoutedCommand mnmsave = new RoutedCommand();
        public static RoutedCommand mnmsaveas = new RoutedCommand();

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public static void mnmExecutedaddrow(object sender, ExecutedRoutedEventArgs e)
        {
            MAC newmac = 0;

            MACAliasMap inst = MACAliasMap.Instance;

            // find unique value for new entry
            while (Instance.table.IndexOf(newmac) != -1) newmac += 1;

            Instance.table.Add(new mnmtable.mnmtableitem(newmac, "new"));
        }
        public static void mnmCanExecuteaddrow(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void mnmExecuteddelrow(object sender, ExecutedRoutedEventArgs e)
        {
            mnmtable.mnmtableitem q = (mnmtable.mnmtableitem)(Instance.dg.SelectedItem);

            MACAliasMap inst = MACAliasMap.Instance;


            Instance.table.Remove(q);
            Instance.mnmchangedsincesavedtodisk = true;
            Instance.NotifyPropertyChanged();
        }
        public static void mnmCanExecutedelrow(object sender, CanExecuteRoutedEventArgs e)
        {
            // only enable if more than one row in table
            // this is a hack - for some reason, if there is only one row in the table and it gets deleted
            // the datagrid is left in some bad state such that the next add operation causes a crash
            // i gave up trying to diagnose it, so my "workaround" is to prevent deletion if there is only one
            // row left
            e.CanExecute = (Instance.table.Count() > 1) && (Instance.dg.SelectedItem != null);
        }
        public static void mnmExecutedsave(object sender, ExecutedRoutedEventArgs e)
        {
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            try
            {
                fs = new FileStream(Instance.mnmfilename, FileMode.Open);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (mnmtable.mnmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.MAC);
                    formatter.Serialize(fs, i.alias);
                }
                Instance.mnmchangedsincesavedtodisk = false;
                fs.Close();
            }
            catch
            {
                MessageBox.Show("Failed to save file");
            }

        }
        public static void mnmCanExecutesave(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (Instance.mnmchangedsincesavedtodisk && (Instance.mnmfilename != null));
        }
        public static void mnmExecutedsaveas(object sender, ExecutedRoutedEventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.FileName = Instance.mnmfilename;
            dlg.DefaultExt = ".MACnamemap";
            dlg.OverwritePrompt = true;

            if (dlg.ShowDialog() == true)
            {
                MACAliasMap inst = Instance;
                Instance.mnmfilename = dlg.FileName;
                fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (mnmtable.mnmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.MAC);
                    formatter.Serialize(fs, i.alias);
                }
                Instance.mnmchangedsincesavedtodisk = false;
                fs.Close();
            }

        }
        public static void mnmCanExecutesaveas(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void mnmExecutedload(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".MACnamemap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                MACAliasMap inst = Instance;

                try
                {
                    // clear existing table entries
                    Instance.table.Clear();

                    Instance.mnmfilename = dlg.FileName;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                        Instance.table.Add(new mnmtable.mnmtableitem((MAC)formatter.Deserialize(fs), (string)formatter.Deserialize(fs)));

                    Instance.mnmchangedsincesavedtodisk = false;
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
        public static void mnmCanExecuteload(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void mnmExecutedappend(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".MACnamemap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                mnmtable dupsexisting = new mnmtable();
                mnmtable dupsnewfile = new mnmtable();
                mnmtable.mnmtableitem item;

                MACAliasMap inst = Instance;

                try
                {
                    // DO NOT clear existing table entriesa
                    // Instance.table.Clear();
                    // Instance.map.Clear();

                    // change the filename to null
                    Instance.mnmfilename = null;
                    Instance.mnmchangedsincesavedtodisk = true;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                    {
                        item = new mnmtable.mnmtableitem((MAC)formatter.Deserialize(fs), (string)formatter.Deserialize(fs));
                        if (Instance.table.IndexOf(item.MAC) != -1)
                        {
                            dupsexisting.Add(new mnmtable.mnmtableitem(item.MAC, Instance.table.Lookup(item.MAC)));
                            dupsnewfile.Add(item);
                        }
                        else Instance.table.Add(item);
                    }
                    if (dupsexisting.Count() != 0)
                    {
                        string s = null;
                        for (int i = 0; i < dupsexisting.Count(); i++)
                        {
                            s += "Existing:\t" + dupsexisting[i].MAC.ToString(false) + " " + dupsexisting[i].alias + "\n";
                            s += "New File:\t" + dupsnewfile[i].MAC.ToString(false) + " " + dupsnewfile[i].alias + "\n\n";
                        }
                        if (MessageBoxResult.Yes == MessageBox.Show(s, "DUPLICATE ENTRIES - USE VALUES FROM APPENDING FILE?", MessageBoxButton.YesNo))
                            for (int i = 0; i < dupsexisting.Count(); i++)
                            {
                                int ix = Instance.table.IndexOf(dupsexisting[i].MAC);
                                Instance.table[ix].alias = dupsnewfile[i].alias;
                            }
                    }


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
        public static void mnmCanExecuteappend(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }





    }



    public class ValidateMAC : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            MAC i = 0;

            if (!i.TryParse((string)value)) return new ValidationResult(false, "Not a valid MAC address");
            else return new ValidationResult(true, "Valid MAC Address");
        }
    }

    public class ValidateMACNonDup : ValidationRule
    // apply regular validation logic, plus check that this is not a duplicate of an entry already in dictionary
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            MAC i = 0;

            if (!i.TryParse((string)value)) return new ValidationResult(false, "Not a valid MAC address");
            else if (MACAliasMap.Instance.table.IndexOf(i) != -1) return new ValidationResult(false, "Duplicate of MAC address already in table");
            else return new ValidationResult(true, "Valid MAC Address");
        }
    }

    public class MACConverter : IValueConverter
    {
        // converts number to/from display format MAC address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((MAC)value).ToString(true);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            MAC i = 0;
            if (i.TryParse((string)value)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class MACConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format MAC address
        // does not convert aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((MAC)value).ToString(false);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            MAC i = 0;
            if (i.TryParse((string)value)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class MACConverterForTooltip : IValueConverter
    {
        // converts number to display format MAC address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((MAC)value).ToStringAlts();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class MACMVConverter : IMultiValueConverter
    {
        // converts number to/from display format MAC address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((MAC)(values[0])).ToString(true);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            MAC i = 0;
            object[] v = new object[3];
            v[0] = (uint)0;
            // set v[1] and v[2] - not sure if they need to be set to their actual values, but not setting them at all leaves
            // them null, and then validation fails even if input if valid
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            if (i.TryParse((string)value))
            {
                v[0] = i;
                return v;
            }
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return v;
        }
    }

    public class MACMVConverterNumberOnly : IMultiValueConverter
    {
        // converts number to/from display format MAC address
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((MAC)(values[0])).ToString(false);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            MAC i = 0;
            object[] v = new object[3];
            v[0] = (uint)0;
            // set v[1] and v[2] - not sure if they need to be set to their actual values, but not setting them at all leaves
            // them null, and then validation fails even if input if valid
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            if (i.TryParse((string)value))
            {
                v[0] = i;
                return v;
            }
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return v;
        }
    }

    public class MACMVConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((MAC)(values[0])).ToStringAlts();
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }







    public class EthernetH : H
    {
        public MAC DestMAC { get; set; }
        public MAC SrcMAC { get; set; }
        public uint TypeLen { get; set; }
        public override string displayinfo { get { return "Ethernet header"; } }


        public EthernetH(FileStream fs, PcapFile pfh, Packet pkt, uint i) : base(fs, pfh, pkt, i)
        {
            if ((pkt.Len - i) < 0xe) return;
            DestMAC = (ulong)pkt.PData[i++] * 0x0010000000000 + (ulong)pkt.PData[i++] * 0x000100000000 + (ulong)pkt.PData[i++] * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            SrcMAC = (ulong)pkt.PData[i++]  * 0x0010000000000 + (ulong)pkt.PData[i++]  * 0x000100000000 + (ulong)pkt.PData[i++]  * 0x000001000000 + (ulong)pkt.PData[i++]  * 0x000000010000 + (ulong)pkt.PData[i++]  * 0x000000000100 + (ulong)pkt.PData[i++] ;
            TypeLen = (uint)pkt.PData[i++]  * 0x100 + (uint)pkt.PData[i++] ;

            // NEED TO HANDLE Q-TAGGED FRAMES
            
            // set generic header properties
            headerprot = Protocols.Ethernet;
            payloadindex = i;
            payloadlen = (int)(pkt.Len - i);

            // set packet-level convenience properties
            pkt.Prots |= Protocols.Ethernet;
            pkt.SrcMAC = SrcMAC;
            pkt.DestMAC = DestMAC;

            pkt.L.Add(this);

            switch (TypeLen)
            {
                case 0x800: //L3Protocol = Protocols.IP4;
                    new IP4H(fs, pfh, pkt, payloadindex);
                    break;
                case 0x806:
                    new ARPH(fs, pfh, pkt, payloadindex);
                    break;
                case 0x8dd: // L3Protocol = Protocols.IPv6;
                    break;
                default:
                    break;
            }
        }
    }



}
