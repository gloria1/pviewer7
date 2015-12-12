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
    class GUIUtil : INotifyPropertyChanged
    // class containing:
    //      utility functions related to displaying hex numbers
    //      global state variables for whether to show them in hex and whether to show aliases
    // this is implemented as a dynamic class as a Singleton, i.e., there can only ever be one instance
    // this is because static classes cannot implement interfaces (or at least INotifyPropertyChanged)
    {
        private static readonly GUIUtil instance = new GUIUtil();
        public static GUIUtil Instance { get { return instance; } }

        private bool _hex;
        public bool Hex { get { return _hex; } set { _hex = value; NotifyPropertyChanged("Hex"); } }
        private bool _usealiases;
        public bool UseAliases { get { return _usealiases; } set { _usealiases = value; NotifyPropertyChanged(); } }

        public int WidthFour {get;} = 4;

        // private constructor below was set up per the "singleton" pattern, so that no further instances of this class could be created
        // however, for some reason this caused the data binding to IP4Hex to stop working, so i have commented this out
        /* private GUIUtil()
        // constructor is private, so no one else can call it - the singleton instance was created in the initialization of Instance above
        {
            return;
        }*/

        // implement INotifyPropertyChanged
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public uint? StringToUInt(string s)
        // converts string to numerical value, respecting state of Hex flag
        // returns null if string cannot be parsed
        {
            NumberStyles style = (Hex ? NumberStyles.HexNumber : NumberStyles.Integer);

            // try to parse, if it fails fall through to return null
            try
            {
                return uint.Parse(s, style);
            }
            catch (FormatException ex)
            {
            }

            return null;
        }

        public string UIntToStringHex(uint value, int width)
        // converts a uint to a string, respecting Hex flag
        // fixed width if width > 0
        {
            string s;

            if (Hex) s = String.Format("{0:x}", value);
            else s = String.Format("{0}", value);

            if (width > 0)
            {
                if (width > s.Length) s.PadLeft(width, '0');
                else s = s.Remove(0, (s.Length - width));
            }

            return s;
        }
        

    }

    class ARPHMVC : IMultiValueConverter
    // takes three arguments
    // first is a string which is returned
    // second and third are ignored, they only exist so that the 
    // multibinding can also bind to the Hex and UseAliases global properties
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return
                "HWType: " + GUIUtil.Instance.UIntToStringHex((uint)values[2], 4)
                + ", Prot: " + GUIUtil.Instance.UIntToStringHex((uint)values[3], 4);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }
    
}
