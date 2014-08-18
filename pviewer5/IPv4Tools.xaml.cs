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


	public class IPv4Tools
	{
		[Serializable]
		public class ipv4namemapclass : Dictionary<ulong, string>
		{
			// need the following constructor (from ISerializable, which is inherited by Dictionary)
			protected ipv4namemapclass(SerializationInfo info, StreamingContext ctx) : base(info, ctx) { }
			// need to explicitly declare an empty constructor, because without this, new tries to use the above constructor
			public ipv4namemapclass() { }

			public ipv4nametableclass maptotable()	// transfers ipv4namemap dictionary to a table to support a datagrid
			{
				ipv4nametableclass table = new ipv4nametableclass();

				foreach (ulong k in this.Keys) table.Add(new inmtableitem(k, this[k]));
				return table;
			}
		}

		[Serializable]
		public class ipv4nametableclass : ObservableCollection<inmtableitem>, INotifyPropertyChanged
		{
			public ipv4namemapclass tabletomap()	// transfers ipv4name table from a datagrid to a ipv4namemap dictionary
			{
				ipv4namemapclass map = new ipv4namemapclass();

				// need to catch exceptions in case table has duplicate ipv4 entries - if this is the case, just return null
				try
				{
					foreach (inmtableitem i in this) map.Add(i.ipv4, i.alias);
				}
				catch
				{
					return null;
				}
				return map;
			}
		}


		public class inmtableitem
		{
			public ulong ipv4 { get; set; }
			public string alias { get; set; }

			public inmtableitem(ulong u, string s)
			{
				this.ipv4 = u;
				this.alias = s;
			}
		}

		public static ipv4namemapclass map = new ipv4namemapclass() 
		{
				{0x000000000000, "ALL ZEROES"},
		};


		public static ulong? StringToIPv4(string s)
		{
			// returns null if string cannot be parsed

			bool hex = MainWindow.ds.DisplayIPv4InHex;
			string regipv4 = (hex ? "^([a-fA-F0-9]{0,2}.){0,3}[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");
			NumberStyles style = (hex ? NumberStyles.HexNumber : NumberStyles.Integer);
			string[] ipv4bits = new string[4];

			try
			{
				return ulong.Parse(s, style);
			}
			catch (FormatException ex)
			{
				if (Regex.IsMatch(s, regipv4))
				{
					ipv4bits = Regex.Split(s, "\\.");
					// resize array to 4 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
					// split will produce array with number of elements equal to nmber of dots + 1
					Array.Resize<string>(ref ipv4bits, 4);

					for (int i = 0; i < 4; i++) { ipv4bits[i] = "0" + ipv4bits[i]; }
					return  ulong.Parse(ipv4bits[0], style) * 0x0000000001000000 +
							ulong.Parse(ipv4bits[1], style) * 0x0000000000010000 +
							ulong.Parse(ipv4bits[2], style) * 0x0000000000000100 +
							ulong.Parse(ipv4bits[3], style) * 0x0000000000000001;
				}
			}

			return null;
		}
		public static string IPv4ToString(ulong value)
		{
			ulong[] b = new ulong[4];
			string s;

			b[0] = ((value & 0xff000000) / 0x1000000);
			b[1] = ((value & 0xff0000) / 0x10000);
			b[2] = ((value & 0xff00) / 0x100);
			b[3] = ((value & 0xff) / 0x1);

			if (MainWindow.ds.DisplayIPv4InHex) s = String.Format("{0:x2}.{1:x2}.{2:x2}.{3:x2}", b[0], b[1], b[2], b[3]);
			else                                s = String.Format("{0}.{1}.{2}.{3}", b[0], b[1], b[2], b[3]);

			return s;
		}
	}

	public class ValidateIPv4Number : ValidationRule
	{
		// validates that string is valid as either raw hex number or ipv4-formatted hex number (using StringToIPv4 function)
		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// try to parse as a raw ipv4 address
			v = IPv4Tools.StringToIPv4((string)value);
			if (v != null) return new ValidationResult(true, "Valid IPv4 Address");
			else return new ValidationResult(false, "Not a valid IPv4 address");
		}
	}

	public class ValidateIPv4NumberOrAlias : ValidationRule
	{
		// validates that string is valid as either raw hex number or ipv4-formatted hex number (using StringToIPv4 function)
		//      or that string is a valid entry in alias registry

		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// first try to parse as a raw ipv4 address
			v = IPv4Tools.StringToIPv4((string)value);
			if (v != null) return new ValidationResult(true, "Valid IPv4 Address");
			// if that failed, see if string exists in ipv4namemap
			foreach (ulong u in IPv4Tools.map.Keys)
				if ((string)value == IPv4Tools.map[u])
					return new ValidationResult(true, "Valid IPv4 Address");
			return new ValidationResult(false, "Not a valid IPv4 address");
		}
	}

	public class IPv4ConverterNumberOnly : IValueConverter
	{
		// converts number to/from display format ipv4 address, without checking the ipv4 alias dictionary

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			return IPv4Tools.IPv4ToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw ipv4 address
			v = IPv4Tools.StringToIPv4((string)value);
			if (v != null) return v;

			// we should never get to this point, since validation step will not pass unless value is either valid raw ipv4 
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process a raw ipv4 address.  Why did this pass validation????");
			return 0;
		}
	}

	public class IPv4ConverterNumberOrAlias : IValueConverter
	{
		// converts number to/from display format ipv4 address, including translating aliases

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			if (MainWindow.ds.DisplayAliases && IPv4Tools.map.ContainsKey((ulong)value)) return IPv4Tools.map[(ulong)value];
			else return IPv4Tools.IPv4ToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw ipv4 address
			v = IPv4Tools.StringToIPv4((string)value);
			if (v != null) return v;

			// if that failed, see if string exists in ipv4namemap
			foreach (ulong u in IPv4Tools.map.Keys)
				if ((string)value == IPv4Tools.map[u])
					return u;

			// we should never get to this point, since validation step will not pass unless value is either valid raw ipv4 or existing entry in ipv4namemap
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process as either raw ipv4 address or entry in ipv4namemap.  Why did this pass validation????");
			return 0;
		}
	}

	public partial class IPv4NameMapDialog : Window
	{
		public static RoutedCommand inmaddrow = new RoutedCommand();

		public IPv4Tools.ipv4nametableclass dgtable { get; set; }

		public IPv4NameMapDialog()
		{
			CommandBinding inmaddrowbinding;

			dgtable = IPv4Tools.map.maptotable();

			InitializeComponent();
			INMDG.DataContext = this;
			inmaddrowbinding = new CommandBinding(inmaddrow, Executedaddrow, CanExecuteaddrow);
			INMDG.CommandBindings.Add(inmaddrowbinding);
			inmaddrowmenuitem.CommandTarget = INMDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly



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

		private void inmAccept(object sender, RoutedEventArgs e)
		{
			IPv4Tools.ipv4namemapclass map = new IPv4Tools.ipv4namemapclass();

			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate ipv4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IPv4 addresses not allowed");
					return;
				}
				else        // else transfer local map to official map and close dialog
				{
					IPv4Tools.map = map;
					DialogResult = true;
					// no need to call Close, since changing DialogResult to non-null automatically closes window
					//Close();
				}
			}

			// do we automatically trigger re-application of filter, or have separate command for that?
			// if/when reapply, need to reset nummatched properties
		}

		private void inmCancel(object sender, RoutedEventArgs e)
		{
			DialogResult = false;
			// no need to call Close, since changing DialogResult to non-null automatically closes window
			//Close();
		}


		private void inmSaveToDisk(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dlg = new SaveFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();
			IPv4Tools.ipv4namemapclass map = new IPv4Tools.ipv4namemapclass();

			// first need to transfer datagrid table to official map
			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors.\nTable not saved.");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate ipv4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IPv4 addresses not allowed.\nTable not saved.");
					return;
				}
				else
				{
					dlg.InitialDirectory = "c:\\pviewer\\";
					dlg.DefaultExt = ".ipv4namemap";
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

		private void inmLoadFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".ipv4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					dgtable = ((IPv4Tools.ipv4namemapclass)formatter.Deserialize(fs)).maptotable();
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					INMDG.ItemsSource = dgtable;
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
		private void inmAppendFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".ipv4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					foreach (IPv4Tools.inmtableitem i in ((IPv4Tools.ipv4namemapclass)formatter.Deserialize(fs)).maptotable()) dgtable.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					INMDG.ItemsSource = dgtable;
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
			IPv4Tools.ipv4nametableclass q;
			DataGrid dg = (DataGrid)e.Source;

			q = (IPv4Tools.ipv4nametableclass)(dg.ItemsSource);

			q.Add(new IPv4Tools.inmtableitem(0, ""));
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
