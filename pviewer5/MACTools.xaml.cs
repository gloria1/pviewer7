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
using System.Text.RegularExpressions;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;



namespace pviewer5
{
    
    public class MACUtil
    // class containing:
    //      utility functions related to MAC addresses (value converters, etc.)
    // this is implemented as a dynamic class as a Singleton, i.e., there can only ever be one instance
    // this is because static classes cannot implement interfaces (or at least INotifyPropertyChanged)
    {

        private static readonly MACUtil instance = new MACUtil();
        public static MACUtil Instance { get { return instance; } }

        // the "official" mac name map which will be used in the value converter
        public macnamemapclass map = new macnamemapclass() 
		    {
				    {0x000000000000, "ALL ZEROES"},
				    {0x2818785702e3, "spr wifi"},
				    {0x00249b097799, "spr ether on usb"},
				    {0x281878b6c14e, "spr ether on dock"},
				    {0xc86000c667df, "win8fs 2"},
				    {0xc86000c65634, "win8fs 4"},
				    {0x5404a62bbb5c, "cnvssd7 3"},
				    {0x000e0cc442ff, "svr 2"},
				    {0xb0c74536471a, "buffalo ether"},
				    {0xb0c745364710, "buffalo 24g"},
				    {0xb0c745364715, "buffalo 5g"}
		    };

        // private constructor below was set up per the "singleton" pattern, so that no further instances of this class could be created
        // however, for some reason this caused the data binding to stop working, so i have commented this out
        /* private MACUtil()
        // constructor is private, so no one else can call it - the singleton instance was created in the initialization of Instance above
        {
            return;
        }*/

        public static string ToString(ulong value, bool usealiasesthistime)
        // if usesaliasesthistime == true, then if global UseAliases is true, and this address has an alias, return the alias
        {
            if (usealiasesthistime && GUIUtil.Instance.UseAliases)
                if (MACUtil.Instance.map.ContainsKey(value))
                    return MACUtil.Instance.map[value];

            ulong[] b = new ulong[6];
            string s;

            b[0] = ((value & 0xff0000000000) / 0x10000000000);
            b[1] = ((value & 0xff00000000) / 0x100000000);
            b[2] = ((value & 0xff000000) / 0x1000000);
            b[3] = ((value & 0xff0000) / 0x10000);
            b[4] = ((value & 0xff00) / 0x100);
            b[5] = ((value & 0xff) / 0x1);

            s = String.Format("{0:x2}:{1:x2}:{2:x2}:{3:x2}:{4:x2}:{5:x2}", b[0], b[1], b[2], b[3], b[4], b[5]);
            return s;
        }

        public static string ToStringAlts(ulong value)
        // return strings of forms other than what would be returned by ToString
        //      if UseAliases, then numerical form
        //      if !UseAliases, then alias if there is one
        {
            if (GUIUtil.Instance.UseAliases) return MACUtil.ToString(value, false);
            else if (MACUtil.Instance.map.ContainsKey(value)) return MACUtil.Instance.map[value];
            else return "no alias";
        }

        public static bool TryParse(string s, ref ulong value)
        // tries to parse string into value
        // first tries to parse a simple hex number
        // if that fails, tries to parse as a numerical : format address
        // if that fails, checks for match of an alias
        // if no match or any errors, returns false and does not assign value
        {
            string regexmac = "^([a-fA-F0-9]{0,2}[-:]){0,5}[a-fA-F0-9]{0,2}$";
            string[] macbits = new string[6];

            // first try to parse as simple hex number
            try
            {
                value = ulong.Parse(s, NumberStyles.HexNumber);
                return true;
            }
            // if that files, try to parse as : notation mac address
            catch (FormatException ex)
            {
                if (Regex.IsMatch(s, regexmac))
                {
                    macbits = Regex.Split(s, "[:-]");
                    // resize array to 6 - we want to tolerate missing colons, i.e., user entering less than 6 segments,
                    // split will produce array with number of elements equal to nmber of colons + 1
                    Array.Resize<string>(ref macbits, 6);

                    for (int i = 0; i < 6; i++) { macbits[i] = "0" + macbits[i]; }

                    try
                    {
                        value = ulong.Parse(macbits[0], NumberStyles.HexNumber) * 0x0000010000000000 +
                                ulong.Parse(macbits[1], NumberStyles.HexNumber) * 0x0000000100000000 +
                                ulong.Parse(macbits[2], NumberStyles.HexNumber) * 0x0000000001000000 +
                                ulong.Parse(macbits[3], NumberStyles.HexNumber) * 0x0000000000010000 +
                                ulong.Parse(macbits[4], NumberStyles.HexNumber) * 0x0000000000000100 +
                                ulong.Parse(macbits[5], NumberStyles.HexNumber) * 0x0000000000000001;
                        return true;
                    }
                    catch { }
                }
                // if we got this far, try to parse as an alias
                foreach (ulong u in MACUtil.Instance.map.Keys)
                    if (s == MACUtil.Instance.map[u])
                    {
                        value = u;
                        return true;
                    }
            }
            // if we got to here, could not parse in any way, return false
            return false;

        }

        /*
        public ulong? StringToMAC(string s)
        // returns null if string cannot be parsed
        {
            string regmac = "^([a-fA-F0-9]{0,2}[-:]){0,5}[a-fA-F0-9]{0,2}$";
            string[] macbits = new string[6];
            try
            {
                return ulong.Parse(s, NumberStyles.HexNumber);
            }
            catch (FormatException ex)
            {
                if (Regex.IsMatch(s, regmac))
                {
                    macbits = Regex.Split(s, "[:-]");
                    // resize array to 6 - we want to tolerate missing colons, i.e., user entering less than 6 segments,
                    // split will produce array with number of elements equal to nmber of colons + 1
                    Array.Resize<string>(ref macbits, 6);

                    for (int i = 0; i < 6; i++) { macbits[i] = "0" + macbits[i]; }

                    try
                    {
                        return ulong.Parse(macbits[0], NumberStyles.HexNumber) * 0x0000010000000000 +
                                ulong.Parse(macbits[1], NumberStyles.HexNumber) * 0x0000000100000000 +
                                ulong.Parse(macbits[2], NumberStyles.HexNumber) * 0x0000000001000000 +
                                ulong.Parse(macbits[3], NumberStyles.HexNumber) * 0x0000000000010000 +
                                ulong.Parse(macbits[4], NumberStyles.HexNumber) * 0x0000000000000100 +
                                ulong.Parse(macbits[5], NumberStyles.HexNumber) * 0x0000000000000001;
                    }
                    catch { }
                }
            }

            return null;
 
       }

        public string MACToString(ulong value)
        {
            ulong[] b = new ulong[6];
            string s;

            b[0] = ((value & 0xff0000000000) / 0x10000000000);
            b[1] = ((value & 0xff00000000) / 0x100000000);
            b[2] = ((value & 0xff000000) / 0x1000000);
            b[3] = ((value & 0xff0000) / 0x10000);
            b[4] = ((value & 0xff00) / 0x100);
            b[5] = ((value & 0xff) / 0x1);

            s = String.Format("{0:x2}:{1:x2}:{2:x2}:{3:x2}:{4:x2}:{5:x2}", b[0], b[1], b[2], b[3], b[4], b[5]);
            return s;
        }
        */

        [Serializable]
        public class macnamemapclass : Dictionary<ulong, string>
        {
            // need the following constructor (from ISerializable, which is inherited by Dictionary)
            protected macnamemapclass(SerializationInfo info, StreamingContext ctx) : base(info, ctx) { }
            // need to explicitly declare an empty constructor, because without this, new tries to use the above constructor
            public macnamemapclass() { }

            public macnametableclass maptotable()	// transfers macnamemap dictionary to a table to support a datagrid
            {
                macnametableclass table = new macnametableclass();

                foreach (ulong k in this.Keys) table.Add(new mnmtableitem(k, this[k]));
                return table;
            }
        }

        //[Serializable]
        public class macnametableclass : ObservableCollection<mnmtableitem> //, INotifyPropertyChanged
        {
            public macnamemapclass tabletomap()	// transfers macname table from a datagrid to a macnamemap dictionary
            {
                macnamemapclass map = new macnamemapclass();

                // need to catch exceptions in case table has duplicate mac entries - if this is the case, just return null
                try
                {
                    foreach (mnmtableitem i in this) map.Add(i.mac, i.alias);
                }
                catch
                {
                    return null;
                }
                return map;
            }
        }

        public class mnmtableitem
        {
            public ulong mac { get; set; }
            public string alias { get; set; }

            public mnmtableitem(ulong u, string s)
            {
                this.mac = u;
                this.alias = s;
            }
        }

 
    }

    public class ValidateMAC : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            ulong i = 0;

            if (MACUtil.TryParse((string)value, ref i)) return new ValidationResult(true, "Valid IP4 Address");
            else return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class MACConverter : IValueConverter
    {
        // converts number to/from display format IP4 address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return MACUtil.ToString((ulong)value, true);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong i = 0;
            if (MACUtil.TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class MACConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format IP4 address
        // does not convert aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return MACUtil.ToString((ulong)value, false);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong i = 0;
            if (MACUtil.TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class MACConverterForTooltip : IValueConverter
    {
        // converts number to display format IP4 address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return MACUtil.ToStringAlts((ulong)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }


    public class MACMVConverter : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return MACUtil.ToString((ulong)values[0], true);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            ulong i = 0;
            object[] v = new object[3];
            v[0] = (ulong)0;

            if (MACUtil.TryParse((string)value, ref i))
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
            return MACUtil.ToStringAlts((ulong)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }





    /*
    public class ValidateMACNumber : ValidationRule
    {
        // validates that string is valid as either raw hex number or mac-formatted hex number (using StringToMAC function)
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            ulong? v = 0;

            // try to parse as a raw mac address
            v = MACUtil.Instance.StringToMAC((string)value);
            if (v != null) return new ValidationResult(true, "Valid MAC Address");
            else return new ValidationResult(false, "Not a valid MAC address");
        }
    }

    public class ValidateMACNumberOrAlias : ValidationRule
    {
        // validates that string is valid as either raw hex number or mac-formatted hex number (using StringToMAC function)
        //      or that string is a valid entry in alias registry

        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            ulong? v = 0;

            if (!(value is string)) return new ValidationResult(false, "Not a valid MAC address");

            // first try to parse as a raw mac address
            v = MACUtil.Instance.StringToMAC((string)value);
            if (v != null) return new ValidationResult(true, "Valid MAC Address");
            // if that failed, see if string exists in macnamemap
            foreach (ulong u in MACUtil.Instance.map.Keys)
                if ((string)value == MACUtil.Instance.map[u])
                    return new ValidationResult(true, "Valid MAC Address");
            return new ValidationResult(false, "Not a valid MAC address");
        }
    }

    public class MACConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format mac address, without checking the mac alias dictionary

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return MACUtil.Instance.MACToString((ulong)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong? v = 0;

            // first try to parse as a raw mac address
            v = MACUtil.Instance.StringToMAC((string)value);
            if (v != null) return v;

            // we should never get to this point, since validation step will not pass unless value is either valid raw mac 
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process a raw mac address.  Why did this pass validation????");
            return 0;
        }
    }

    public class MACConverterNumberOrAlias : IValueConverter
    {
        // converts number to/from display format mac address, including translating aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && MACUtil.Instance.map.ContainsKey((ulong)value)) return MACUtil.Instance.map[(ulong)value];
            else return MACUtil.Instance.MACToString((ulong)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong? v = 0;

            // first try to parse as a raw mac address
            v = MACUtil.Instance.StringToMAC((string)value);
            if (v != null) return v;

            // if that failed, see if string exists in macnamemap
            foreach (ulong u in MACUtil.Instance.map.Keys)
                if ((string)value == MACUtil.Instance.map[u])
                    return u;

            // we should never get to this point, since validation step will not pass unless value is either valid raw mac or existing entry in macnamemap
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process as either raw mac address or entry in macnamemap.  Why did this pass validation????");
            return 0;
        }
    }

    public class MACConverterNumberOrAliasForTooltip : IValueConverter
    {
        // converts number to/from display format mac address, including translating aliases
        // uses inverse of GUIUtil.UseAliases property - to feed tooltip

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!GUIUtil.Instance.UseAliases && MACUtil.Instance.map.ContainsKey((ulong)value)) return MACUtil.Instance.map[(ulong)value];
            else return MACUtil.Instance.MACToString((ulong)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class MACMultiConverterNumberOrAlias : IMultiValueConverter
    {
        // converts number to/from display format MAC address, including translating aliases
        // also takes value of UseAliases as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && MACUtil.Instance.map.ContainsKey((ulong)values[0]))
                return MACUtil.Instance.map[(ulong)values[0]];
            else return MACUtil.Instance.MACToString((ulong)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            ulong? u;
            object[] v = new object[3];
            // copy current values of hex and usealiases into result to be sent back - multi value converter must pass back values for all bindings in the multibinding
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            // first try to parse as a raw IP4 address
            u = MACUtil.Instance.StringToMAC((string)value);
            if (u != null)
            {
                v[0] = u;
                return v;
            }

            // if that failed, see if string exists in IP4namemap
            foreach (ulong uu in MACUtil.Instance.map.Keys)
                if ((string)value == MACUtil.Instance.map[uu])
                {
                    v[0] = uu;
                    return v;
                }

            // we should never get to this point, since validation step will not pass unless value is either valid raw IP4 or existing entry in IP4namemap
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process as either raw IP4 address or entry in IP4namemap.  Why did this pass validation????");
            v[0] = 0; return v;
        }

    }

    public class MACMultiConverterNumberOrAliasForTooltip : IMultiValueConverter
    // same as above except respects inverse of UseAliases, to feed tooltip
    {
        // converts number to/from display format MAC address, including translating aliases
        // also takes value of UseAliases as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && MACUtil.Instance.map.ContainsKey((ulong)values[0]))
                return MACUtil.Instance.map[(ulong)values[0]];
            else return MACUtil.Instance.MACToString((ulong)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }

    */


    public partial class MACNameMapDialog : Window, INotifyPropertyChanged
	{
		public static RoutedCommand mnmaddrow = new RoutedCommand();
		public MACUtil.macnametableclass dgtable {get;set;}

        private bool _chgsincesave = false;
        public bool changedsincesavedtodisk { get { return _chgsincesave; } set { _chgsincesave = value; NotifyPropertyChanged(); } }
        private bool _chgsinceapplied = false;
        public bool changedsinceapplied { get { return _chgsinceapplied; } set { _chgsinceapplied = value; NotifyPropertyChanged(); } }

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


        public MACNameMapDialog()
		{
			CommandBinding mnmaddrowbinding;

			dgtable = MACUtil.Instance.map.maptotable();
			
			InitializeComponent();
            buttonbar.DataContext = this;
			MNMDG.DataContext = this;
			mnmaddrowbinding = new CommandBinding(mnmaddrow, Executedaddrow, CanExecuteaddrow);
			MNMDG.CommandBindings.Add(mnmaddrowbinding);
			mnmaddrowmenuitem.CommandTarget = MNMDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly

		}

		public bool IsValid(DependencyObject parent)
		{
			// this is from http://stackoverflow.com/questions/17951045/wpf-datagrid-validation-haserror-is-always-false-mvvm

			if (Validation.GetHasError(parent))
				return false;

			// Validate all the bindings on the children
			for (int i = 0; i != VisualTreeHelper.GetChildrenCount(parent); ++i)
			{
				DependencyObject child = VisualTreeHelper.GetChild(parent, i);
				if (!IsValid(child)) { return false; }
			}

			return true;
		}
		private void mnmApply(object sender, RoutedEventArgs e)
		{
			MACUtil.macnamemapclass map = new MACUtil.macnamemapclass();

			if (!IsValid(mnmgrid))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate macs, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate MAC addresses not allowed");
					return;
				}
				else        // else transfer local map to official map and close dialog
				{
                    changedsinceapplied = false;
					MACUtil.Instance.map = map;
                    GUIUtil.Instance.UseAliases = GUIUtil.Instance.UseAliases; // no-op but will cause change notifications to view
                }
			}
		}

        private void mnmAccept(object sender, RoutedEventArgs e)
        {
            mnmApply(this, null);
            Close();
        }

        private void mnmCancel(object sender, RoutedEventArgs e)
		{
			Close();
		}

        private void mnmcelleditending(object sender, DataGridCellEditEndingEventArgs e)
        // handle CellEditEnding event from the datagrid
        {
            changedsinceapplied = true;
            changedsincesavedtodisk = true;
        }

        private void mnmSaveToDisk(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dlg = new SaveFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();
			MACUtil.macnamemapclass map = new MACUtil.macnamemapclass();

			// first need to transfer datagrid table to official map
			if (!IsValid(mnmgrid))
			{
				MessageBox.Show("Resolve Validation Errors.\nTable not saved.");
				return;
			}
			else 
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate macs, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate MAC addresses not allowed.\nTable not saved.");
					return;
				}
				else
				{
					dlg.InitialDirectory = "c:\\pviewer\\";
					dlg.DefaultExt = ".macnamemap";
					dlg.OverwritePrompt = true;

					if (dlg.ShowDialog() == true)
					{
						fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
						formatter.Serialize(fs, map);
                        changedsincesavedtodisk = false;
						fs.Close();
					}
				}
			}
		}
		private void mnmLoadFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".macnamemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					dgtable = ((MACUtil.macnamemapclass)formatter.Deserialize(fs)).maptotable();
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					MNMDG.ItemsSource = dgtable;
                    changedsincesavedtodisk = false;
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
		private void mnmAppendFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".macnamemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					foreach(MACUtil.mnmtableitem i in ((MACUtil.macnamemapclass)formatter.Deserialize(fs)).maptotable()) dgtable.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					MNMDG.ItemsSource = dgtable;
                    changedsincesavedtodisk = true;
				}
				catch
				{
					MessageBox.Show("File not read"); fs.Close(); return; 
				}
				finally 
				{
					fs.Close();
				}
			}
		}
		private static void Executedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			MACUtil.macnametableclass q;
			DataGrid dg = (DataGrid)e.Source;

			q = (MACUtil.macnametableclass)(dg.ItemsSource);

			q.Add(new MACUtil.mnmtableitem(0, ""));
		}
		private static void PreviewExecutedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
		}
		private static void CanExecuteaddrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}


	}
}
