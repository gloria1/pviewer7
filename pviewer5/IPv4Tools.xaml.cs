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


	public class IP4Tools
	{
		[Serializable]
		public class IP4namemapclass : Dictionary<ulong, string>
		{
			// need the following constructor (from ISerializable, which is inherited by Dictionary)
			protected IP4namemapclass(SerializationInfo info, StreamingContext ctx) : base(info, ctx) { }
			// need to explicitly declare an empty constructor, because without this, new tries to use the above constructor
			public IP4namemapclass() { }

			public IP4nametableclass maptotable()	// transfers IP4namemap dictionary to a table to support a datagrid
			{
				IP4nametableclass table = new IP4nametableclass();

				foreach (ulong k in this.Keys) table.Add(new inmtableitem(k, this[k]));
				return table;
			}
		}

		[Serializable]
		public class IP4nametableclass : ObservableCollection<inmtableitem>, INotifyPropertyChanged
		{
			public IP4namemapclass tabletomap()	// transfers IP4name table from a datagrid to a IP4namemap dictionary
			{
				IP4namemapclass map = new IP4namemapclass();

				// need to catch exceptions in case table has duplicate IP4 entries - if this is the case, just return null
				try
				{
					foreach (inmtableitem i in this) map.Add(i.IP4, i.alias);
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
			public ulong IP4 { get; set; }
			public string alias { get; set; }

			public inmtableitem(ulong u, string s)
			{
				this.IP4 = u;
				this.alias = s;
			}
		}

		public static IP4namemapclass map = new IP4namemapclass() 
		{
				{0x000000000000, "ALL ZEROES"},
		};


		public static ulong? StringToIP4(string s)
		{
			// returns null if string cannot be parsed

			bool hex = MainWindow.ds.DisplayIP4InHex;
			string regIP4 = (hex ? "^([a-fA-F0-9]{0,2}.){0,3}[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");
			NumberStyles style = (hex ? NumberStyles.HexNumber : NumberStyles.Integer);
			string[] IP4bits = new string[4];

			try
			{
				return ulong.Parse(s, style);
			}
			catch (FormatException ex)
			{
				if (Regex.IsMatch(s, regIP4))
				{
					IP4bits = Regex.Split(s, "\\.");
					// resize array to 4 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
					// split will produce array with number of elements equal to nmber of dots + 1
					Array.Resize<string>(ref IP4bits, 4);

					for (int i = 0; i < 4; i++) { IP4bits[i] = "0" + IP4bits[i]; }
					return  ulong.Parse(IP4bits[0], style) * 0x0000000001000000 +
							ulong.Parse(IP4bits[1], style) * 0x0000000000010000 +
							ulong.Parse(IP4bits[2], style) * 0x0000000000000100 +
							ulong.Parse(IP4bits[3], style) * 0x0000000000000001;
				}
			}

			return null;
		}
		public static string IP4ToString(ulong value)
		{
			ulong[] b = new ulong[4];
			string s;

			b[0] = ((value & 0xff000000) / 0x1000000);
			b[1] = ((value & 0xff0000) / 0x10000);
			b[2] = ((value & 0xff00) / 0x100);
			b[3] = ((value & 0xff) / 0x1);

			if (MainWindow.ds.DisplayIP4InHex) s = String.Format("{0:x2}.{1:x2}.{2:x2}.{3:x2}", b[0], b[1], b[2], b[3]);
			else                                s = String.Format("{0}.{1}.{2}.{3}", b[0], b[1], b[2], b[3]);

			return s;
		}
	}

	public class ValidateIP4Number : ValidationRule
	{
		// validates that string is valid as either raw hex number or IP4-formatted hex number (using StringToIP4 function)
		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// try to parse as a raw IP4 address
			v = IP4Tools.StringToIP4((string)value);
			if (v != null) return new ValidationResult(true, "Valid IP4 Address");
			else return new ValidationResult(false, "Not a valid IP4 address");
		}
	}

	public class ValidateIP4NumberOrAlias : ValidationRule
	{
		// validates that string is valid as either raw hex number or IP4-formatted hex number (using StringToIP4 function)
		//      or that string is a valid entry in alias registry

		public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
		{
			ulong? v = 0;

			// first try to parse as a raw IP4 address
			v = IP4Tools.StringToIP4((string)value);
			if (v != null) return new ValidationResult(true, "Valid IP4 Address");
			// if that failed, see if string exists in IP4namemap
			foreach (ulong u in IP4Tools.map.Keys)
				if ((string)value == IP4Tools.map[u])
					return new ValidationResult(true, "Valid IP4 Address");
			return new ValidationResult(false, "Not a valid IP4 address");
		}
	}

	public class IP4ConverterNumberOnly : IValueConverter
	{
		// converts number to/from display format IP4 address, without checking the IP4 alias dictionary

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			return IP4Tools.IP4ToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw IP4 address
			v = IP4Tools.StringToIP4((string)value);
			if (v != null) return v;

			// we should never get to this point, since validation step will not pass unless value is either valid raw IP4 
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process a raw IP4 address.  Why did this pass validation????");
			return 0;
		}
	}

	public class IP4ConverterNumberOrAlias : IValueConverter
	{
		// converts number to/from display format IP4 address, including translating aliases

		public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
		{
			if (MainWindow.ds.DisplayAliases && IP4Tools.map.ContainsKey((ulong)value)) return IP4Tools.map[(ulong)value];
			else return IP4Tools.IP4ToString((ulong)value);
		}

		public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
		{
			ulong? v = 0;

			// first try to parse as a raw IP4 address
			v = IP4Tools.StringToIP4((string)value);
			if (v != null) return v;

			// if that failed, see if string exists in IP4namemap
			foreach (ulong u in IP4Tools.map.Keys)
				if ((string)value == IP4Tools.map[u])
					return u;

			// we should never get to this point, since validation step will not pass unless value is either valid raw IP4 or existing entry in IP4namemap
			// however, just in case put up a messagebox and return 0
			MessageBox.Show("ConvertBack could not process as either raw IP4 address or entry in IP4namemap.  Why did this pass validation????");
			return 0;
		}
	}

	public partial class IP4NameMapDialog : Window
	{
		public static RoutedCommand inmaddrow = new RoutedCommand();

		public IP4Tools.IP4nametableclass dgtable { get; set; }

		public IP4NameMapDialog()
		{
			CommandBinding inmaddrowbinding;

			dgtable = IP4Tools.map.maptotable();

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
			IP4Tools.IP4namemapclass map = new IP4Tools.IP4namemapclass();

			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate IP4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IP4 addresses not allowed");
					return;
				}
				else        // else transfer local map to official map and close dialog
				{
					IP4Tools.map = map;
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
			IP4Tools.IP4namemapclass map = new IP4Tools.IP4namemapclass();

			// first need to transfer datagrid table to official map
			if (!IsValid(inmgrid))
			{
				MessageBox.Show("Resolve Validation Errors.\nTable not saved.");
				return;
			}
			else
			{
				map = dgtable.tabletomap();
				if (map == null)		// if error transferring table due to duplicate IP4s, inform user and return to dialog		
				{
					MessageBox.Show("Duplicate IP4 addresses not allowed.\nTable not saved.");
					return;
				}
				else
				{
					dlg.InitialDirectory = "c:\\pviewer\\";
					dlg.DefaultExt = ".IP4namemap";
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
			dlg.DefaultExt = ".IP4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					dgtable = ((IP4Tools.IP4namemapclass)formatter.Deserialize(fs)).maptotable();
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
			dlg.DefaultExt = ".IP4namemap";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					foreach (IP4Tools.inmtableitem i in ((IP4Tools.IP4namemapclass)formatter.Deserialize(fs)).maptotable()) dgtable.Add(i);
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
			IP4Tools.IP4nametableclass q;
			DataGrid dg = (DataGrid)e.Source;

			q = (IP4Tools.IP4nametableclass)(dg.ItemsSource);

			q.Add(new IP4Tools.inmtableitem(0, ""));
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
