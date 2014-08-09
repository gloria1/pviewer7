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
		[Serializable]
		public class QuickFilter : ObservableCollection<QFItem>
		{
		}

		[Serializable]
		public class QFItem
		{
			public QFIncl inclusion {get; set;}
			public ulong mask {get; set;}
			public ulong value {get; set;}
			public bool active {get; set;}
			public ulong nummatched {get; set;}
		}

		public enum QFIncl { Include, Exclude }   // Include means if this criterion is matched, include the packet

		// list of items in the QFIncl enumeration, to support the ItemsSource of the gui textbox
		public static List<QFIncl> QFInclItems = new List<QFIncl>() { QFIncl.Include, QFIncl.Exclude };

		// the "official" quickfilter
		public static QuickFilter QF = new QuickFilter();
	}

	// BOOKMARK
	// working on setting up datagrid columsn for qfdialog
	// need to distinguish between MAC and IP filters
	// MAC/IP column should be combobox that allows selection of existing alias strings


	public partial class QuickFilterDialog : Window
	{
		public static RoutedCommand qfaddrow = new RoutedCommand();
		public QuickFilterTools.QuickFilter qflocal {get;set;}
		
		public QuickFilterDialog()
		{
			CommandBinding qfaddrowbinding;

			// make local copy of quickfilter; changes will not be committed to qfarg until validated and user chooses to accept them
			qflocal = new QuickFilterTools.QuickFilter();
			foreach (QuickFilterTools.QFItem q in QuickFilterTools.QF) qflocal.Add(q);

			InitializeComponent();
			QFMACDG.DataContext = this;
			qfaddrowbinding = new CommandBinding(qfaddrow, Executedaddrow, CanExecuteaddrow);
			QFMACDG.CommandBindings.Add(qfaddrowbinding);
			qfmacaddrowmenuitem.CommandTarget = QFMACDG;   // added this so that menu command would not be disabled when datagrid first created; not sure exactly why this works, books/online articles refer to WPF not correctly determining the intended command target based on focus model (logical focus? keyboard focus?), so you have to set the command target explicitly

	// BOOKMARK
	// CHANGING QUICKFILTER STRUCTURE TO SIMPLE LIST (OBSERVABLE COLLECTION ACTUALLY)
	// WILL RELY ON BRUTE FORCE TO TEST EACH PACKET AGAINST THE LIST
	// NOW THE DIALOG DATAGRID CAN BIND DIRECTLY TO THE QUICKFILTER
	// Next steps:

			//		checkboxes to toggle aliasing of mac/ip addresses
			//		protocol column s.b. combo
			//		value converter for macs, ips, to format address
			//		allow input in hex
			//		allow input in mac, ip format
			//		drag and drop
			//		add/delete row respect multi selections



			/*
			 * MAINTENTANCE
			 *		PUT GIT USERNAME AND EMAIL INTO WINES
			 *				CMSUCHAR
			 *				CMSUCHAR@VERIZON.NET
			 *				
			 * MUSIC ON IPHONE
			 * MUSIC ON SD CARD
			 * CHANGE VIDS ON SD CARD
			 */

		}


		/*		 *   qfwindow:  dialog to add, delete and switch active/inactive
		 *		separate class from qf
		 *		constructor takes reference to a qf as argument, copies data into local ObservableCollection for a datagrid
		 *		event handlers for 
		 *			apply (and re-filter loaded packets)
		 *			cancel
		 *			save to disk
		 *			load from disk
		 *			append from disk
		 *			insert a row (or multiple, if selection is multiple?)
		 *			delete a row (or group of rows?)
		 *			drag/drop row (or groups of rows?)
		 *			(support disjoint multiple selections????)
				*/
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
			if (!IsValid(QFMACDG))
			{
				MessageBox.Show("Resolve Validation Errors");
				return;
			}
			else
			{
				QuickFilterTools.QF.Clear();
				foreach (QuickFilterTools.QFItem q in qflocal) QuickFilterTools.QF.Add(q);
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
			if (!IsValid(QFMACDG))
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
					formatter.Serialize(fs, qflocal);
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
					qflocal = ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs));
					// next command re-sets ItemsSource, window on screen does not update to show new contents of qflocal, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					QFMACDG.ItemsSource = qflocal;
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
					foreach(QuickFilterTools.QFItem i in ((QuickFilterTools.QuickFilter)formatter.Deserialize(fs))) qflocal.Add(i);
					// next command re-sets ItemsSource, window on screen does not update to show new contents of dgtable, don't know why
					// there is probably some mechanism to get the display to update without re-setting the ItemsSource, but this seems to work
					QFMACDG.ItemsSource = qflocal;
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
			QuickFilterTools.QuickFilter q;
			DataGrid dg = (DataGrid)e.Source;
			QuickFilterDialog qd = (QuickFilterDialog)dg.DataContext;

			qd.qflocal.Add(new QuickFilterTools.QFItem());
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
