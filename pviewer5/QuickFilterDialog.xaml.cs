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


    public class QuickFilterTools
    {
        // list of items in the QFIncl enumeration, to support the ItemsSource of the gui textbox
        public static List<QFIncl> QFInclItems = new List<QFIncl>() { QFIncl.Include, QFIncl.Exclude };

        // the "official" quickfilters
        public static QuickFilter QFMAC = new QuickFilter();
        public static QuickFilter QFIP4 = new QuickFilter();

        [Serializable]
        public class QuickFilter : ObservableCollection<QFItem>
        {
            public bool Exclude(ulong value)
            {
                bool exclude = false;

                foreach (QFItem i in this)
                    if (i.active)
                        if ((value & i.mask) == i.value)
                        {
                            i.nummatched++;
                            if (i.inclusion == QFIncl.Include) return false;	// if matched an inclusion criteria, immediately return false
                            else exclude = true;								// else set the "Exclude" flag to true
                        }
                return exclude;				// if we passed through whole foreach loop, then no inclusion criteria were met
                // so return value of exclude flag, which will be true if any exclusion criterion was met
            }

            public void ResetCounters()
            {
                foreach (QFItem i in this) i.nummatched = 0;
            }

        }

        [Serializable]
        public class QFItem
        {
            public QFIncl inclusion { get; set; }
            public ulong mask { get; set; }
            public ulong value { get; set; }
            public bool active { get; set; }
            public ulong nummatched { get; set; }
        }

        public enum QFIncl { Include, Exclude }   // Include means if this criterion is matched, include the packet

    }

    
    
    public partial class QuickFilterDialog : Window
	{
		public static RoutedCommand qfmacaddrow = new RoutedCommand();
		public static RoutedCommand qfIP4addrow = new RoutedCommand();
		public QuickFilterTools.QuickFilter qfmaclocal { get; set; }
		public QuickFilterTools.QuickFilter qfIP4local { get; set; }
		
		public QuickFilterDialog()
		{
			CommandBinding qfmacaddrowbinding;
			CommandBinding qfIP4addrowbinding;

			// make local copy of quickfilter; changes will not be committed to official copies until validated and user chooses to accept them
			qfmaclocal = new QuickFilterTools.QuickFilter();
			foreach (QuickFilterTools.QFItem q in QuickFilterTools.QFMAC) qfmaclocal.Add(q);
			qfIP4local = new QuickFilterTools.QuickFilter();
			foreach (QuickFilterTools.QFItem q in QuickFilterTools.QFIP4) qfIP4local.Add(q);

			InitializeComponent();
			QFMACDG.DataContext = this;
			qfmacaddrowbinding = new CommandBinding(qfmacaddrow, Executedmacaddrow, CanExecutemacaddrow);
			QFMACDG.CommandBindings.Add(qfmacaddrowbinding);
			qfmacaddrowmenuitem.CommandTarget = QFMACDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly
			QFIP4DG.DataContext = this;
			qfIP4addrowbinding = new CommandBinding(qfIP4addrow, ExecutedIP4addrow, CanExecuteIP4addrow);
			QFIP4DG.CommandBindings.Add(qfIP4addrowbinding);
			qfIP4addrowmenuitem.CommandTarget = QFIP4DG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly

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
		private void QFDAccept(object sender, RoutedEventArgs e)
		{
			if (!(IsValid(QFMACDG) && IsValid(QFIP4DG)))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				QuickFilterTools.QFMAC.Clear();
				foreach (QuickFilterTools.QFItem q in qfmaclocal) QuickFilterTools.QFMAC.Add(q);
				QuickFilterTools.QFIP4.Clear();
				foreach (QuickFilterTools.QFItem q in qfIP4local) QuickFilterTools.QFIP4.Add(q);
				DialogResult = true;
				// no need to call Close, since changing DialogResult to non-null automatically closes window
				//Close();
			}

			// do we automatically trigger re-application of filter, or have separate command for that?
			// if/when reapply, need to reset nummatched properties
		}
		private void QFDCancel(object sender, RoutedEventArgs e)
		{
			DialogResult = false;
			// no need to call Close, since changing DialogResult to non-null automatically closes window
			//Close();
		}
		private void QFDSaveToDisk(object sender, RoutedEventArgs e)
		{
			SaveFileDialog dlg = new SaveFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			// first need to transfer datagrid table to official map
			if (!(IsValid(QFMACDG) && IsValid(QFIP4DG)))
			{
				MessageBox.Show("Resolve Validation Errors.\nTable not saved.");
				return;
			}
			else 
			{
				dlg.InitialDirectory = "c:\\pviewer\\";
				dlg.DefaultExt = ".quickfilter";
				dlg.OverwritePrompt = true;

				if (dlg.ShowDialog() == true)
				{
					fs = new FileStream(dlg.FileName, FileMode.OpenOrCreate);
					formatter.Serialize(fs, qfmaclocal);
					formatter.Serialize(fs, qfIP4local);
					fs.Close();
				}
			}
		}
		private void QFDLoadFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".quickfilter";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					qfmaclocal = ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs));
					qfIP4local = ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs));
					// next command re-sets ItemsSource, window on screen does not update to show new contents of qflocal, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					QFMACDG.ItemsSource = qfmaclocal;
					QFIP4DG.ItemsSource = qfIP4local;
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
		private void QFDAppendFromDisk(object sender, RoutedEventArgs e)
		{
			OpenFileDialog dlg = new OpenFileDialog();
			FileStream fs;
			IFormatter formatter = new BinaryFormatter();

			dlg.InitialDirectory = "c:\\pviewer\\";
			dlg.DefaultExt = ".quickfilter";
			dlg.Multiselect = false;

			if (dlg.ShowDialog() == true)
			{
				fs = new FileStream(dlg.FileName, FileMode.Open);

				try
				{
					foreach(QuickFilterTools.QFItem i in ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs))) qfmaclocal.Add(i);
					foreach (QuickFilterTools.QFItem i in ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs))) qfIP4local.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					QFMACDG.ItemsSource = qfmaclocal;
					QFMACDG.ItemsSource = qfIP4local;
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
		private static void Executedmacaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			QuickFilterTools.QuickFilter q;
			DataGrid dg = (DataGrid)e.Source;
			QuickFilterDialog qd = (QuickFilterDialog)dg.DataContext;

			qd.qfmaclocal.Add(new QuickFilterTools.QFItem());
		}
// needed?
	//	private static void PreviewExecutedmacaddrow(object sender, ExecutedRoutedEventArgs e)
	//	{
	//	}
		private static void CanExecutemacaddrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}
		private static void ExecutedIP4addrow(object sender, ExecutedRoutedEventArgs e)
		{
			QuickFilterTools.QuickFilter q;
			DataGrid dg = (DataGrid)e.Source;
			QuickFilterDialog qd = (QuickFilterDialog)dg.DataContext;

			qd.qfIP4local.Add(new QuickFilterTools.QFItem());
		}
		private static void PreviewExecutedIP4addrow(object sender, ExecutedRoutedEventArgs e)
		{
		}
		private static void CanExecuteIP4addrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}

	}




}
