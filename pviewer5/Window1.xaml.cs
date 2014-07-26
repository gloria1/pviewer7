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

	public class listrow
	{
		public bool onoff { get; set; }
		public string text1 { get; set; }
		public string text2 { get; set; }

		public listrow(bool c, string t1, string t2)
		{
			onoff = c;
			text1 = t1;
			text2 = t2;
		}
	}



	public partial class Window1 : Window
	{
		public static ObservableCollection<listrow> list { get; set; }

		public static RoutedCommand LAdd = new RoutedCommand();
		public CommandBinding LAddBinding;

		public Window1()
		{
			InitializeComponent();

			list = new ObservableCollection<listrow>();
			list.Add(new listrow(true, "11", "12"));
			list.Add(new listrow(true, "21", "22"));
			list.Add(new listrow(true, "31", "32"));

			W1Grid.DataContext = this;
			LAddBinding = new CommandBinding(LAdd, ExecutedLadd, CanExecuteLadd);
			w1dg.CommandBindings.Add(LAddBinding);
		}

		private static void ExecutedLadd(object sender, ExecutedRoutedEventArgs e)
		{
			DataGridCell cell = (DataGridCell)e.OriginalSource;
			DataGrid dg = (DataGrid)sender;
			for (int i = dg.SelectedItems.Count; i > 0; i--) list.Add(new listrow(false, String.Format("{0}", 100 * i + 1), String.Format("{0}", 100 * i + 2)));


			MessageBox.Show("ExecutedLadd function - actually executes the command");
		}
		private static void CanExecuteLadd(object sender, CanExecuteRoutedEventArgs e)
		{
			Control target = e.Source as Control;
			if (target != null) { e.CanExecute = true; }
			else { e.CanExecute = false; }
		}

	}
}


/* key elements of command setup:
 * 
 * 1) declare RoutedCommand  intance - needs to be static
 * 2) declare CommandBinding instance - links command, Executed event handler and CanExecute event handler
 * 3) in MainWindow, add binding to target ui element (at highest level where it might apply i think), via
 *			object.CommandBindings.Add
 * 4) create event handlers for Executed and CanExecute
 * 5) in xaml, at to declaration of command source (button, menuitem, etc.):
 *			Command="{commandname}"
 *			commandname can be one of the standard library commands, or a custom command
 *			custom commands require declaration of the appropriate xaml namespace so that the c# command name is recognizeable in the xaml (don't understand all this yet)
 * 
 */

