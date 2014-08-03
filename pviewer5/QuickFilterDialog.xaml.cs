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

namespace pviewer5
{
	public enum QFIncl { Include, Exclude }   // Include means if this criterion is matched, include the packet

	public class QFItem
	{
		public static List<QFIncl> QFInclItems = new List<QFIncl>() { QFIncl.Include, QFIncl.Exclude };

		public QFIncl inclusion {get; set;}
		public ulong mask {get; set;}
		public ulong value {get; set;}
		public bool active {get; set;}
		public ulong nummatched {get; set;}
	}


	// BOOKMARK
	// working on setting up datagrid columsn for qfdialog
	// need to distinguish between MAC and IP filters
	// MAC/IP column should be combobox that allows selection of existing alias strings


	
	
	
	
	
	public partial class QuickFilterDialog : Window
	{
		public static RoutedCommand qfaddrow = new RoutedCommand();
		public ObservableCollection<QFItem> qfproperty { get; set; }
		
		public QuickFilterDialog(ObservableCollection<QFItem> qfarg)
		{
			CommandBinding qfaddrowbinding;

			qfproperty = qfarg;

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
		private void QFDAccept(object sender, RoutedEventArgs e)
		{
			// do we automatically trigger re-application of filter, or have separate command for that?
			// if/when reapply, need to reset nummatched properties
		}
		private void QFDCancel(object sender, RoutedEventArgs e)
		{
		}
		private void QFDSaveToDisk(object sender, RoutedEventArgs e)
		{
		}
		private void QFDLoadFromDisk(object sender, RoutedEventArgs e)
		{
		}
		private void QFDAppendFromDisk(object sender, RoutedEventArgs e)
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
