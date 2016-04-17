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
    public struct IP4
    {
        public uint A;

        public override bool Equals(object a)
        {
            if (a == DependencyProperty.UnsetValue) return false;
            else return ((IP4)a).A == A;
        }
        public override int GetHashCode() { return A.GetHashCode(); }
        public static implicit operator IP4(uint i) { IP4 r = new IP4(); r.A = i; return r; }
        public static IP4 operator +(IP4 a, IP4 b) { IP4 r = new IP4(); r.A = a.A + b.A; return r; }
        public static IP4 operator *(IP4 a, IP4 b) { IP4 r = new IP4(); r.A = a.A * b.A; return r; }
        public static IP4 operator &(IP4 a, IP4 b) { IP4 r = new IP4(); r.A = a.A & b.A; return r; }
        public static IP4 operator |(IP4 a, IP4 b) { IP4 r = new IP4(); r.A = a.A | b.A; return r; }
        public static bool operator ==(IP4 a, IP4 b) { return a.A == b.A; }
        public static bool operator !=(IP4 a, IP4 b) { return a.A != b.A; }
        public static bool operator <=(IP4 a, IP4 b) { return a.A <= b.A; }
        public static bool operator <(IP4 a, IP4 b) { return a.A < b.A; }
        public static bool operator >=(IP4 a, IP4 b) { return a.A >= b.A; }
        public static bool operator >(IP4 a, IP4 b) { return a.A > b.A; }

        public override string ToString() { return ToString(false, true); }

        public string ToString(bool inverthex, bool usealiasesthistime)
        // if inverthex==true, return based on !Hex
        // if usealiasesthistime == true, then if global UseAliases is true, return the alias
        {
            if (usealiasesthistime && GUIUtil.Instance.UseAliases)
            {
                int aliasindex;

                 aliasindex = IP4AliasMap.Instance.table.IndexOf(A);
                 if (aliasindex != -1) return IP4AliasMap.Instance.table.Lookup(A);
            }

            uint[] b = new uint[4];
            string s;

            b[0] = ((A & 0xff000000) / 0x1000000);
            b[1] = ((A & 0xff0000) / 0x10000);
            b[2] = ((A & 0xff00) / 0x100);
            b[3] = ((A & 0xff) / 0x1);

            if (inverthex ^ GUIUtil.Instance.Hex) s = String.Format("{0:x2}.{1:x2}.{2:x2}.{3:x2}", b[0], b[1], b[2], b[3]);
            else s = String.Format("{0}.{1}.{2}.{3}", b[0], b[1], b[2], b[3]);

            return s;
        }

        public string ToStringAlts()
        // return strings of forms other than what would be returned by ToString
        //      numerical form indicated by !Hex
        //      if UseAliases, then numerical form based on Hex
        //      if !UseAliases, then alias if there is one
        {
            string s = null;
            int aliasindex;
            s = ToString(true, false);
            s += "\n";
            aliasindex = IP4AliasMap.Instance.table.IndexOf(A);
            if (aliasindex != -1)
            {
                // if UseAliases, then, if this IP has an alias, we want to append the non-inverthex numerical form
                if (GUIUtil.Instance.UseAliases) s += ToString(false, false);
                // else return the alias
                else s += IP4AliasMap.Instance.table.Lookup(A);
            }

            return s;
        }

        public bool TryParse(string s)
        // tries to parse string into A
        // first tries to parse a simple number, respecting global Hex flag
        // if that fails, tries to parse as a numerical dot format address, respecting global Hex flag
        // if that fails, checks for match of an alias
        // if no match or any errors, returns false and does not assign value
        {
            // first try to parse as a raw IP4 address
            string[] IP4bits = new string[4];
            NumberStyles style = (GUIUtil.Instance.Hex ? NumberStyles.HexNumber : NumberStyles.Integer);
            string regexIP4 = (GUIUtil.Instance.Hex ? "^(0*[a-fA-F0-9]{0,2}.){0,3}0*[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");

            try
            {
                A = uint.Parse(s, style);
                return true;
            }
            // if could not parse as simple number
            catch (FormatException ex)
            {
                // try parsing as dot notation
                if (Regex.IsMatch(s, regexIP4))
                {
                    IP4bits = Regex.Split(s, "\\.");
                    // resize array to 4 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
                    // split will produce array with number of elements equal to nmber of dots + 1
                    Array.Resize<string>(ref IP4bits, 4);

                    for (int i = 0; i < 4; i++) { IP4bits[i] = "0" + IP4bits[i]; }

                    try
                    {
                        A = uint.Parse(IP4bits[0], style) * 0x0000000001000000 +
                            uint.Parse(IP4bits[1], style) * 0x0000000000010000 +
                            uint.Parse(IP4bits[2], style) * 0x0000000000000100 +
                            uint.Parse(IP4bits[3], style) * 0x0000000000000001;
                        return true;
                    }
                    catch { }
                }
                // if we have gotten this far, s was not parsed as a simple number or dot notation number, so check if it is a valid alias
                foreach (IP4AliasMap.inmtable.inmtableitem it in IP4AliasMap.Instance.table)
                    if (s == it.alias)
                    {
                        A = it.IP4.A;
                        return true;
                    }

                // if we get to here, s could not be parsed in any valid way, so return false;
                return false;
            }

        }

    }




    public class IP4AliasMap : INotifyPropertyChanged
    {
        public static IP4AliasMap Instance = null;
        public IP4AliasMap()
        {
            if (Instance != null) MessageBox.Show("Something is instantiating a second instance of IP4AliasMap, which should never happen.");
            else Instance = this;
        }

        // view model for mapping of IP4 values to aliases
        // needs to be non-static so that it can be part of an instance that
        // is referenced by the MainWindow instance so that the xaml can
        // reference it in a databinding

        public class inmtable : ObservableCollection<inmtable.inmtableitem>
        {
            // backing model for ip4 name map - it is a dictionary since we want to be able to look up by just indexing the map with an ip4 address
            // this is private so there is no way anything outside this class can alter the dictionary  without updating the table
            // i.e., all external access to the map will be through the table
            private Dictionary<IP4, string> dict = new Dictionary<IP4, string>();

            public new void Add(inmtableitem it)
            // return without doing anything if it is a duplicate of an IP4 already in table
            {
                if (IndexOf(it.IP4) == -1)
                {
                    it.parent = this;
                    base.Add(it);
                    dict.Add(it.IP4, it.alias);
                }
            }
            public new bool Remove(inmtableitem it)
            {
                int ix = IndexOf(it.IP4);
                if (ix == -1) return false;
                else return RemoveAt(ix);
            }
            public string Lookup(IP4 ip)
            {
                return dict[ip];
            }
            public int IndexOf(IP4 ip)
            {
                for (int i = 0; i < this.Count(); i++) if (this[i].IP4 == ip) return i;
                return -1;
            }
            public new bool RemoveAt(int i)
            {
                if ((i < 0) || (i >= this.Count())) return false;
                dict.Remove(this[i].IP4);
                base.RemoveAt(i);
                return true;
            }
            public new void Clear()
            {
                base.Clear();
                dict.Clear();
            }


            public class inmtableitem : INotifyPropertyChanged
            {
                public inmtable parent = null;
                private IP4 _ip4;
                public IP4 IP4
                {
                    get { return _ip4; }
                    set
                    {
                        // fail if this ip4 is a duplicate of one already in the dictionary 
                        // this should never happen
                        // gui validator logic should prevent it
                        if (parent != null)
                        {
                            if (parent.IndexOf(value) != -1)
                            {
                                MessageBox.Show("ATTEMPT TO CREATE DUPLICATE ADDRESS IN IP4 NAME MAP\nTHIS SHOULD NEVER HAPPEN\nGUI VALIDATION LOGIC SHOULD PREVENT THIS");
                                return;
                            }

                            // need to update dict to keep in sync - i think we need to delete old item and add a new one
                            string s = parent.Lookup(_ip4);
                            parent.dict.Remove(_ip4);
                            parent.dict.Add(value, s);
                            _ip4 = value;

                            // if this is part of the main gui viewmodel, update the dirty flag
                            if (parent == Instance.table) Instance.inmchangedsincesavedtodisk = true;
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
                        if (parent != null) parent.dict[_ip4] = value;
                        if (parent == Instance.table) Instance.inmchangedsincesavedtodisk = true;
                        
                        NotifyPropertyChanged();        // notify the gui
                        GUIUtil.Instance.UseAliases = GUIUtil.Instance.UseAliases;    // this will trigger notifications of any other gui items that use aliases
                    }
                }

                public inmtableitem(IP4 u, string s)
                {
                    _ip4 = u;
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

        public inmtable table { get; set; } = new inmtable();

        // reference to datagrid this table is bound to
        public DataGrid dg = null;

        private string _inmfilename = null;
        public string inmfilename { get { return _inmfilename; }set { _inmfilename = value; NotifyPropertyChanged(); } }
        public bool inmchangedsincesavedtodisk = false;

        public static RoutedCommand inmaddrow = new RoutedCommand();
        public static RoutedCommand inmdelrow = new RoutedCommand();
        public static RoutedCommand inmload = new RoutedCommand();
        public static RoutedCommand inmappend = new RoutedCommand();
        public static RoutedCommand inmsave = new RoutedCommand();
        public static RoutedCommand inmsaveas = new RoutedCommand();

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public bool inmIsValid(DependencyObject parent)
        {
            // this is from http://stackoverflow.com/questions/17951045/wpf-datagrid-validation-haserror-is-always-false-mvvm

            if (Validation.GetHasError(parent))
                return false;

            // Validate all the bindings on the children
            for (int i = 0; i != VisualTreeHelper.GetChildrenCount(parent); ++i)
            {
                DependencyObject child = VisualTreeHelper.GetChild(parent, i);
                if (!inmIsValid(child)) { return false; }
            }

            return true;
        }
        
        public static void inmExecutedaddrow(object sender, ExecutedRoutedEventArgs e)
        {
            IP4 newip4 = 0;

            IP4AliasMap inst = IP4AliasMap.Instance;

            // find unique value for new entry
            while (Instance.table.IndexOf(newip4) != -1) newip4 += 1;

            Instance.table.Add(new inmtable.inmtableitem(newip4, "new"));
        }
        public static void inmCanExecuteaddrow(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void inmExecuteddelrow(object sender, ExecutedRoutedEventArgs e)
        {
            inmtable.inmtableitem q = (inmtable.inmtableitem)(Instance.dg.SelectedItem);

            IP4AliasMap inst = IP4AliasMap.Instance;


            Instance.table.Remove(q);
            Instance.inmchangedsincesavedtodisk = true;
            Instance.NotifyPropertyChanged();
        }
        public static void inmCanExecutedelrow(object sender, CanExecuteRoutedEventArgs e)
        {
            // only enable if more than one row in table
            // this is a hack - for some reason, if there is only one row in the table and it gets deleted
            // the datagrid is left in some bad state such that the next add operation causes a crash
            // i gave up trying to diagnose it, so my "workaround" is to prevent deletion if there is only one
            // row left
            e.CanExecute = (Instance.table.Count() > 1) && (Instance.dg.SelectedItem != null);
        }
        public static void inmExecutedsave(object sender, ExecutedRoutedEventArgs e)
        {
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            try
            {
                fs = new FileStream(Instance.inmfilename, FileMode.Open);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (inmtable.inmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.IP4);
                    formatter.Serialize(fs, i.alias);
                }
                Instance.inmchangedsincesavedtodisk = false;
                fs.Close();
            }
            catch
            {
                MessageBox.Show("Failed to save file");
            }

        }
        public static void inmCanExecutesave(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (Instance.inmchangedsincesavedtodisk && (Instance.inmfilename!= null));
        }
        public static void inmExecutedsaveas(object sender, ExecutedRoutedEventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.FileName = Instance.inmfilename;
            dlg.DefaultExt = ".IP4namemap";
            dlg.OverwritePrompt = true;

            if (dlg.ShowDialog() == true)
            {
                IP4AliasMap inst = Instance;
                Instance.inmfilename = dlg.FileName;
                fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
                formatter.Serialize(fs, Instance.table.Count());
                foreach (inmtable.inmtableitem i in Instance.table)
                {
                    formatter.Serialize(fs, i.IP4);
                    formatter.Serialize(fs, i.alias);
                }
                Instance.inmchangedsincesavedtodisk = false;
                fs.Close();
            }

        }
        public static void inmCanExecutesaveas(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void inmExecutedload(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".IP4namemap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                IP4AliasMap inst = Instance;

                try
                {
                    // clear existing table entries
                    Instance.table.Clear();

                    Instance.inmfilename = dlg.FileName;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                        Instance.table.Add(new inmtable.inmtableitem((IP4)formatter.Deserialize(fs), (string)formatter.Deserialize(fs)));

                    Instance.inmchangedsincesavedtodisk = false;
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
        public static void inmCanExecuteload(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }
        public static void inmExecutedappend(object sender, ExecutedRoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            dlg.InitialDirectory = "c:\\pviewer\\";
            dlg.DefaultExt = ".IP4namemap";
            dlg.Multiselect = false;

            if (dlg.ShowDialog() == true)
            {
                fs = new FileStream(dlg.FileName, FileMode.Open);

                inmtable dupsexisting = new inmtable();
                inmtable dupsnewfile = new inmtable();
                inmtable.inmtableitem item;

                IP4AliasMap inst = Instance;

                try
                {
                    // DO NOT clear existing table entriesa
                    // Instance.table.Clear();
                    // Instance.map.Clear();

                    // change the filename to null
                    Instance.inmfilename = null;
                    Instance.inmchangedsincesavedtodisk = true;

                    for (int i = (int)formatter.Deserialize(fs); i > 0; i--)
                    {
                        item = new inmtable.inmtableitem((IP4)formatter.Deserialize(fs), (string)formatter.Deserialize(fs));
                        if (Instance.table.IndexOf(item.IP4) != -1)
                        {
                            dupsexisting.Add(new inmtable.inmtableitem(item.IP4, Instance.table.Lookup(item.IP4)));
                            dupsnewfile.Add(item);
                        }
                        else Instance.table.Add(item);
                    }
                    if (dupsexisting.Count() != 0)
                    {
                        string s = null;
                        for (int i = 0; i < dupsexisting.Count(); i++)
                        {
                            s += "Existing:\t" + dupsexisting[i].IP4.ToString(false, false) + " " + dupsexisting[i].alias + "\n";
                            s += "New File:\t" + dupsnewfile[i].IP4.ToString(false, false) + " " + dupsnewfile[i].alias + "\n\n";
                        }
                        if (MessageBoxResult.Yes == MessageBox.Show(s, "DUPLICATE ENTRIES - USE VALUES FROM APPENDING FILE?", MessageBoxButton.YesNo))
                            for (int i = 0; i < dupsexisting.Count(); i++)
                            {
                                int ix = Instance.table.IndexOf(dupsexisting[i].IP4);
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
        public static void inmCanExecuteappend(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = true;
        }



    }




    public class ValidateIP4 : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            IP4 i = 0;

            if (!i.TryParse((string)value)) return new ValidationResult(false, "Not a valid IP4 address");
            else return new ValidationResult(true, "Valid IP4 Address");
        }
    }

    public class ValidateIP4NonDup : ValidationRule
    // apply regular validation logic, plus check that this is not a duplicate of an entry already in dictionary
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            IP4 i = 0;

            if (!i.TryParse((string)value)) return new ValidationResult(false, "Not a valid IP4 address");
            else if (IP4AliasMap.Instance.table.IndexOf(i) != -1) return new ValidationResult(false, "Duplicate of IP4 address already in table");
            else return new ValidationResult(true, "Valid IP4 Address");
        }
    }

    public class IP4Converter : IValueConverter
    {
        // converts number to/from display format IP4 address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((IP4)value).ToString(false, true);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            IP4 i = 0;
            if (i.TryParse((string)value)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class IP4ConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format IP4 address
        // does not convert aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((IP4)value).ToString(false, false);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            IP4 i = 0;
            if (i.TryParse((string)value)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class IP4ConverterForTooltip : IValueConverter
    {
        // converts number to display format IP4 address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return ((IP4)value).ToStringAlts();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class IP4MVConverter : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((IP4)(values[0])).ToString(false, true);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            IP4 i = 0;
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

    public class IP4MVConverterNumberOnly : IMultiValueConverter
    {
        // converts number to/from display format IP4 address
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((IP4)(values[0])).ToString(false, false);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            IP4 i = 0;
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

    public class IP4MVConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            // handle UnsetValue - this comes to the converter when gui objects are getting initialized and are not fully bound to their data source yet
            if (values[0] == DependencyProperty.UnsetValue) return "";
            else return ((IP4)(values[0])).ToStringAlts();
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }



    public class IP4H : H
    {
        public uint Ver { get; set; }
        public uint HdrLen { get; set; }
        public uint TOS { get; set; }
        public uint Len { get; set; }
        public uint Ident { get; set; }
        public uint DontFrag { get; set; }
        public uint MoreFrags { get; set; }
        public uint FragOffset { get; set; }
        public uint TTL { get; set; }
        public uint Prot { get; set; }
        public uint Checksum { get; set; }
        public IP4 SrcIP4 { get; set; }
        public IP4 DestIP4 { get; set; }
        public uint OptionLen { get; set; }

        public override string displayinfo
        {
            get
            {
                return String.Format("IPv4 header, Protocol = {0:X4}, Src IP = ", Prot)
                    + SrcIP4.ToString(false, true)
                    + ", Dest IP = "
                    + DestIP4.ToString(false, true);
            }
        }


        public IP4H(FileStream fs, PcapFile pfh, Packet pkt, uint i)
        {
            if ((pkt.Len - i) < 0x1) return;
            HdrLen = (uint)pkt.PData[i++] ;
            Ver = (HdrLen & 0xf0) / 16; // note we keep this value in number of 32 bit words
            HdrLen &= 0x0f;   // mask out the high 4 bits that contain the version
            if ((pkt.Len - i) < (4 * HdrLen)) return; // if not enough bytes, this is not a valid header

            TOS = (uint)pkt.PData[i++] ;
            Len = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            Ident = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            FragOffset = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            DontFrag = (FragOffset & 0x4000) / 0x4000;
            MoreFrags = (FragOffset & 0x2000) / 0x2000;
            FragOffset &= 0x1fff;
            TTL = (uint)pkt.PData[i++] ;
            Prot = (uint)pkt.PData[i++] ;
            Checksum = (uint)pkt.PData[i++]  * 0x0100 + (uint)pkt.PData[i++] ;
            SrcIP4 = (IP4)pkt.PData[i++]  * 0x01000000 + (IP4)pkt.PData[i++]  * 0x00010000 + (IP4)pkt.PData[i++]  * 0x0100 + (IP4)pkt.PData[i++] ;
            DestIP4 = (IP4)pkt.PData[i++]  * 0x01000000 + (IP4)pkt.PData[i++]  * 0x00010000 + (IP4)pkt.PData[i++]  * 0x0100 + (IP4)pkt.PData[i++] ;

            OptionLen = (HdrLen * 4) - 0x14;
            i += OptionLen;

            // HANDLE OPTIONS

            // set generic header properties
            payloadlen = (int)(Len - HdrLen * 4);
            payloadindex = i;
            headerprot = Protocols.IP4;

            // set packet level convenience properties
            pkt.Prots |= Protocols.IP4;
            pkt.SrcIP4 = SrcIP4;
            pkt.DestIP4 = DestIP4;
            pkt.ip4hdr = this;

            // add to header list
            pkt.phlist.Add(this);
            
            switch (Prot)
            {
                case 0x01: //L4Protocol = Protocols.ICMP;
                    new ICMPH(fs, pfh, pkt, i);
                    break;
                case 0x02: // L4Protocol = Protocols.IGMP;
                    break;
                case 0x03: // L4Protocol = Protocols.GGP;
                    break;
                case 0x06: //L4Protocol = Protocols.TCP;
                    new TCPH(fs, pfh, pkt, i);
                    break;
                case 0x11: // L4Protocol = Protocols.UDP;
                    new UDPH(fs, pfh, pkt, i);
                    break;

                default:
                    break;
            }
        }
    }


}