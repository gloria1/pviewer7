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

namespace pviewer5
{

	public class MACTools
	{

		public static Dictionary<ulong, string> macnamemap = new Dictionary<ulong, string>() 
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
			foreach (ulong u in MACTools.macnamemap.Keys)
				if ((string)value == MACTools.macnamemap[u])
					return new ValidationResult(true, "Valid MAC Address");
			return new ValidationResult(false, "Not a valid MAC address");
		}
	}

	public class MACConverterNumberOnly : IValueConverter
	{
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
		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			if (MainWindow.ds.DisplayAliases && MACTools.macnamemap.ContainsKey((ulong)value)) return MACTools.macnamemap[(ulong)value];
			else return MACTools.MACToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
			if (v != null) return v;

			// if that failed, see if string exists in macnamemap
			foreach (ulong u in MACTools.macnamemap.Keys)
				if ((string)value == MACTools.macnamemap[u])
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

		public class mnmitem {
			public ulong mac {get; set;}
			public string alias {get; set;}

			public mnmitem(ulong u, string s)
			{
				this.mac = u;
				this.alias = s; 
			}
		}
		public ObservableCollection<mnmitem> mi { get; set; }

		public MACNameMapDialog()
		{
			CommandBinding mnmaddrowbinding;

			mi = new ObservableCollection<mnmitem>();
			foreach (ulong u in MACTools.macnamemap.Keys)
				mi.Add(new mnmitem(u, MACTools.macnamemap[u]));
			
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
			if (IsValid(mnmgrid))
			{
				MACTools.macnamemap.Clear();

				// we have not validated earlier that the list of macs is unique
				// it must be unique to be translated back into a dictionary key for MACTools.macnamemap
				foreach (mnmitem i in MNMDG.ItemsSource)
				{
					try
					{
						MACTools.macnamemap.Add(i.mac, i.alias);
					}
					catch
					{
						MessageBox.Show("Duplicate MAC addresses not allowed");
						return;
					}
				}
				DialogResult = true;
				// no need to call Close, since changing DialogResult to non-null automatically closes window
				//Close();
			}
			else MessageBox.Show("Resolve Validation Errors");


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
		}
		private void mnmLoadFromDisk(object sender, RoutedEventArgs e)
		{
		}
		private void mnmAppendFromDisk(object sender, RoutedEventArgs e)
		{
		}
		private static void Executedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			ObservableCollection<mnmitem> q;
			DataGrid dg = (DataGrid)e.Source;

			q = (ObservableCollection<mnmitem>)(dg.ItemsSource);

			q.Add(new mnmitem(0, ""));
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
