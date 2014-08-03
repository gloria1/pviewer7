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



	// to add:
	// Dialog to edit mac name map dictionary - add, delete, edit, load/save
	//   use same datagrid code as quickfilter dialog

	
	
	
	
	
	
	
	
	
	
	public class MACTools
	{
		public static ulong? StringToMAC(string s)
		{
			string regmac = "^([a-fA-F0-9]{0,2}:){0,5}[a-fA-F0-9]{0,2}$";
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

	public class ValidateMACInput : ValidationRule
	{
		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
			if (v != null) return new ValidationResult(true, "Valid MAC Address");

			// if that failed, see if string exists in macnamemap
			foreach (ulong u in MACConverter.macnamemap.Keys)
				if ((string)value == MACConverter.macnamemap[u])
					return new ValidationResult(true, "Valid MAC Address");

			return new ValidationResult(false, "Not a valid MAC address");
		}
	}

	public class MACConverter : IValueConverter
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

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			if (MainWindow.ds.DisplayAliases && macnamemap.ContainsKey((ulong)value)) return macnamemap[(ulong)value];
			else return MACTools.MACToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw mac address
			v = MACTools.StringToMAC((string)value);
			if (v != null) return v;

			// if that failed, see if string exists in macnamemap
			foreach (ulong u in MACConverter.macnamemap.Keys)
				if ((string)value == MACConverter.macnamemap[u])
					return u;

			// we should never get to this point, since validation step will not pass unless value is either valid raw mac or existing entry in macnamemap
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process as either raw mac address or entry in macnamemap.  Why did this pass validation????");
			return 0;
		}
	}

	public partial class MACInputDialog : Window
	{
		public static RoutedCommand mnmaddrow = new RoutedCommand();

		public struct mnmitem {
			public ulong mac {get; set;}
			public string alias {get; set;}

			public mnmitem(ulong u, string s) : this()
			{ this.mac = u; this.alias = s; }
		}

		public ObservableCollection<mnmitem> mi { get; set; }

		public MACInputDialog()
		{
			CommandBinding mnmaddrowbinding;

			mi = new ObservableCollection<mnmitem>();
			foreach (ulong u in MACConverter.macnamemap.Keys)
				mi.Add(new mnmitem(u, MACConverter.macnamemap[u]));
			
			InitializeComponent();
			MNMDG.DataContext = this;
			mnmaddrowbinding = new CommandBinding(mnmaddrow, Executedaddrow, CanExecuteaddrow);
			MNMDG.CommandBindings.Add(mnmaddrowbinding);
			mnmaddrowmenuitem.CommandTarget = MNMDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly



			// add handlers for 
			//		addrow
			//		accept (do not allow if validation errors
			//			ideally, disable button when validation errors occur)
			//		cancel
			//		file save/load/append from



		}


		private void mnmAccept(object sender, RoutedEventArgs e)
		{
			// do we automatically trigger re-application of filter, or have separate command for that?
			// if/when reapply, need to reset nummatched properties


			// put macs and aliases back to MACConverter.macnamemap

/*			if (!Validation.GetHasError(input))
			{
				macresult = macentered;
				this.DialogResult = true;
				//Close(); not necessary, setting dialogresult to true automatically closes
			}
*/
			// if there is a validation error, ignore the ok button
		
		}
		private void mnmCancel(object sender, RoutedEventArgs e)
		{
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
			ObservableCollection<QFItem> q;
			DataGrid dg = (DataGrid)e.Source;

			q = (ObservableCollection<QFItem>)(dg.ItemsSource);
			q.Add(new QFItem());
		}
		private static void PreviewExecutedaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			MessageBox.Show("PreviewExecutedqfdaddrow function - actually executes the command");
		}
		private static void CanExecuteaddrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}


	}
}
