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


	public class MACTools
	{
		[Serializable]
		public class macnamemapclass : Dictionary<ulong, string>
		{
			// need the following constructor (from ISerializable, which is inherited by Dictionary)
			protected macnamemapclass(SerializationInfo info, StreamingContext ctx) : base(info, ctx) {}
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

		// the "official" mac name map which will be used in the value converter
		public static macnamemapclass map = new macnamemapclass() 
		{
				{0x000000000000, "ALL ZEROES"},
				{0xc86000c65634, "win8fs 4"},
				{0x5404a62bbb5c, "cnvssd7 3"},
				{0x000e0cc442ff, "svr 2"},
				{0xb0c74536471a, "buffalo ether"},
				{0xb0c745364710, "buffalo 24g"},
				{0xb0c745364715, "buffalo 5g"}
		};


		public static ulong? StringToMAC(string s)
		{
			// returns null if string cannot be parsed


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
					macbits = Regex.Split(s, ":");
					// resize array to 6 - we want to tolerate missing colons, i.e., user entering less than 6 segments,
					// split will produce array with number of elements equal to nmber of colons + 1
					Array.Resize<string>(ref macbits,6);
		
					for (int i=0;i<6;i++) {macbits[i] = "0" + macbits[i]; }
					return  ulong.Parse(macbits[0], NumberStyles.HexNumber) * 0x0000010000000000 +
							ulong.Parse(macbits[1], NumberStyles.HexNumber) * 0x0000000100000000 +
							ulong.Parse(macbits[2], NumberStyles.HexNumber) * 0x0000000001000000 +
							ulong.Parse(macbits[3], NumberStyles.HexNumber) * 0x0000000000010000 +
							ulong.Parse(macbits[4], NumberStyles.HexNumber) * 0x0000000000000100 +
							ulong.Parse(macbits[5], NumberStyles.HexNumber) * 0x0000000000000001;
				}
			}

			return null;
		}
		public static string MACToString(ulong value)
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
	}

	public class ValidateMACNumber : ValidationRule
	{
		// validates that string is valid as either raw hex number or mac-formatted hex number (using StringToMAC function)
		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
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

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
			if (v != null) return new ValidationResult(true, "Valid MAC Address");
			// if that failed, see if string exists in macnamemap
			foreach (ulong u in MACTools.map.Keys)
				if ((string)value == MACTools.map[u])
					return new ValidationResult(true, "Valid MAC Address");
			return new ValidationResult(false, "Not a valid MAC address");
		}
	}

	public class MACConverterNumberOnly : IValueConverter
	{
		// converts number to/from display format mac address, without checking the mac alias dictionary

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			return MACTools.MACToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
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
			if (MainWindow.ds.DisplayAliases && MACTools.map.ContainsKey((ulong)value)) return MACTools.map[(ulong)value];
			else return MACTools.MACToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
			if (v != null) return v;

			// if that failed, see if string exists in macnamemap
			foreach (ulong u in MACTools.map.Keys)
				if ((string)value == MACTools.map[u])
					return u;

			// we should never get to this point, since validation step will not pass unless value is either valid raw mac or existing entry in macnamemap
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process as either raw mac address or entry in macnamemap.  Why did this pass validation????");
			return 0;
		}
	}

	public partial class MACNameMapDialog : Window
	{
		public static RoutedCommand mnmaddrow = new RoutedCommand();
		public MACTools.macnametableclass dgtable {get;set;}

		public MACNameMapDialog()
		{
			CommandBinding mnmaddrowbinding;

			dgtable = MACTools.map.maptotable();
			
			InitializeComponent();
			MNMDG.DataContext = this;
			mnmaddrowbinding = new CommandBinding(mnmaddrow, Executedaddrow, CanExecuteaddrow);
			MNMDG.CommandBindings.Add(mnmaddrowbinding);
			mnmaddrowmenuitem.CommandTarget = MNMDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly



			// add handlers for 
			//		file save/load/append from



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
		private void mnmAccept(object sender, RoutedEventArgs e)
		{
			MACTools.macnamemapclass map = new MACTools.macnamemapclass();

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
					MACTools.map = map;
					DialogResult = true;
					// no need to call Close, since changing DialogResult to non-null automatically closes window
					//Close();
				}
			}

			// do we automatically trigger re-application of filter, or have separate command for that?
			// if/when reapply, need to reset nummatched properties
		}
		private void mnmCancel(object sender, RoutedEventArgs e)
		{
			DialogResult = false;
			// no need to call Close, since changing DialogResult to non-null automatically closes window
			//Close();
		}
		private void mnmSaveToDisk(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dlg = new SaveFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();
			MACTools.macnamemapclass map = new MACTools.macnamemapclass();

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
					dgtable = ((MACTools.macnamemapclass)formatter.Deserialize(fs)).maptotable();
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					MNMDG.ItemsSource = dgtable;
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
					foreach(MACTools.mnmtableitem i in ((MACTools.macnamemapclass)formatter.Deserialize(fs)).maptotable()) dgtable.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					MNMDG.ItemsSource = dgtable;
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
			MACTools.macnametableclass q;
			DataGrid dg = (DataGrid)e.Source;

			q = (MACTools.macnametableclass)(dg.ItemsSource);

			q.Add(new MACTools.mnmtableitem(0, ""));
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
