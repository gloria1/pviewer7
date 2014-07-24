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

	public class QFIndiv
	{
		public bool active;
		public ulong nummatched;
	}		// properties associated with an individual quickfilter criterion

	public class QFIndivSet		// a dictionary, where the key is an ip or mac address and the value is QFIndiv, i.e., properties associated with that address
	{
		public Dictionary<ulong, QFIndiv> set = new Dictionary<ulong, QFIndiv>();

		public bool match(ulong value)
		{
			if (set.ContainsKey(value))
				if (set[value].active)
				{
					set[value].nummatched++;
					return true;
				}
				else return false;
			else return false;
		}
	}

	public class QuickFilter	// a filter consisting of dictionaries for criteria to include or exclude based on mac or ip
	// for each dictionary, the key is the mask to be applied to the subject value, and the value is the QFIndivSet of criteria that use that mask
	{
		public Dictionary<ulong, QFIndivSet> exclmac = new Dictionary<ulong, QFIndivSet>();	// key will be the mask for each set
		public Dictionary<ulong, QFIndivSet> exclip = new Dictionary<ulong, QFIndivSet>();	// key will be the mask for each set
		public Dictionary<ulong, QFIndivSet> inclmac = new Dictionary<ulong, QFIndivSet>();	// key will be the mask for each set
		public Dictionary<ulong, QFIndivSet> inclip = new Dictionary<ulong, QFIndivSet>();	// key will be the mask for each set

		public bool includebasedonmac(ulong value)
		{
			bool exclcriterionmet = false;	// default result is to include

			foreach (ulong mask in exclmac.Keys)
			{
				if (exclmac[mask].match(value & mask))
				{
					exclcriterionmet = true;	// exclusion criteria say this packet should be excluded (pending test vs. inclusion criteria)
					break;				// no need to test against other exclusion criteria
				}
			}
			if (!exclcriterionmet) return true;	// if no exclusion criteria met, no need to test against inclusion criteria
			else
			{								// if we are in this branch, an exclusion criterion was met, so we test against inclusion criteria
				//     if an inclusion criterion is satisfied, that overrides the exclusion criteria
				foreach (ulong mask in inclmac.Keys)
				{
					if (exclmac[mask].match(value & mask)) return true;	// if match an inclusion criterion, we are done and return true
				}
				return false;	// if we got this far, then an exclusion criterion was met and no inclusion criteria met, so result is false
			}
		}
		public bool includebasedonip(ulong value)
		{
			bool exclcriterionmet = false;	// default result is to include

			foreach (ulong mask in exclip.Keys)
			{
				if (exclmac[mask].match(value & mask))
				{
					exclcriterionmet = true;	// exclusion criteria say this packet should be excluded (pending test vs. inclusion criteria)
					break;				// no need to test against other exclusion criteria
				}
			}
			if (!exclcriterionmet) return true;	// if no exclusion criteria met, no need to test against inclusion criteria
			else
			{								// if we are in this branch, an exclusion criterion was met, so we test against inclusion criteria
				//     if an inclusion criterion is satisfied, that overrides the exclusion criteria
				foreach (ulong mask in inclip.Keys)
				{
					if (exclmac[mask].match(value & mask)) return true;	// if match an inclusion criterion, we are done and return true
				}
				return false;	// if we got this far, then an exclusion criterion was met and no inclusion criteria met, so result is false
			}
		}
	}

	public partial class QuickFilterDialog : Window
	{

		public struct qfditems
		{
			public ulong mask { get; set; }
			public ulong value { get; set; }
			public bool active {get;set;}
		}
		public ObservableCollection<qfditems> exclmac { get; set; }
		public ObservableCollection<qfditems> inclmac { get; set; }
		public ObservableCollection<qfditems> exclip { get; set; }
		public ObservableCollection<qfditems> inclip { get; set; }

		public static RoutedCommand qfdaddrow = new RoutedCommand();
		public CommandBinding qfdaddrowbinding;

		public QuickFilterDialog(QuickFilter qf)
		{
			exclmac = new ObservableCollection<qfditems>();
			inclmac = new ObservableCollection<qfditems>();
			exclip = new ObservableCollection<qfditems>();
			inclip = new ObservableCollection<qfditems>();


			// make local copy of quick filter, in ObservableCollections to back data grids
			qfditems qi = new qfditems();
			qi.mask = 1; qi.value = 2; qi.active = true;

			exclmac.Add(qi);

			InitializeComponent();
			QFDgrid.DataContext = this;
			// does not work if instantiate the command inside the constructor
			// qfdaddrow = new RoutedCommand();
			qfdaddrowbinding = new CommandBinding(qfdaddrow, Executedqfdaddrow, CanExecuteqfdaddrow);
			//qfdaddrowbinding.PreviewExecuted += PreviewExecutedqfdaddrow;
			ExclMACDG.CommandBindings.Add(qfdaddrowbinding);
			
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
		private static void Executedqfdaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			MessageBox.Show("Executedqfdaddrow function - actually executes the command");
		}
		private static void PreviewExecutedqfdaddrow(object sender, ExecutedRoutedEventArgs e)
		{
			MessageBox.Show("PreviewExecutedqfdaddrow function - actually executes the command");
		}
		private static void CanExecuteqfdaddrow(object sender, CanExecuteRoutedEventArgs e)
		{
			e.CanExecute = true;
		}

	}




}
