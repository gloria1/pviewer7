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
        public bool Hex { get { return _hex; } set { _hex = value;
   //             ICollectionView udpgroupview = (ICollectionView)CollectionViewSource.GetDefaultView(MainWindow.grouptree.ItemsSource);


                NotifyPropertyChanged("Hex"); } }
        private bool _usealiases;
        public bool UseAliases { get { return _usealiases; } set { _usealiases = value; NotifyPropertyChanged(); } }

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
        // fixed width if width > 0 and Hex==true
        {
            string s;

            if (Hex) s = String.Format("{0:x}", value);
            else s = String.Format("{0}", value);

            if ((width > 0) && Hex)
            {
                if (width > s.Length) s=s.PadLeft(width, '0');
                else s = s.Remove(0, (s.Length - width));
            }

            return s;
        }

        public string UIntToStringHexInverse(uint value, int width)
        // converts a uint to a string, respecting INVERSE OF Hex flag
        // fixed width if width > 0 and Hex==true
        {
            string s;

            if (!Hex) s = String.Format("{0:x}", value);
            else s = String.Format("{0}", value);

            if ((width > 0) && Hex)
            {
                if (width > s.Length) s = s.PadLeft(width, '0');
                else s = s.Remove(0, (s.Length - width));
            }

            return s;
        }

    }


    public class ValidateUInt16Number : ValidationRule
    {
        // validates that string is valid as either raw hex number or IP4-formatted hex number (using StringToIP4 function)
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            uint? v = 0;

            // try to parse as a uint 16 bit value
            v = GUIUtil.Instance.StringToUInt(value.ToString());
            if (v == null) return new ValidationResult(false, "Not a valid UInt");
            else if (v > 0xffff) return new ValidationResult(false, "Value Out of Bounds for UInt16");
            else return new ValidationResult(true, "Valid UInt16");
        }
    }

 

    public class UInt16Converter : IValueConverter
    {
        // converts number to/from display format UInt 16 bit

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.Instance.UIntToStringHex((uint)value, 4);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            ulong? v = 0;

            // first try to parse as a raw IP4 address
            v = GUIUtil.Instance.StringToUInt((string)value);
            if (v == null) return 0;
            else if (v > 0xffff) return 0xffff;
            else return v;
        }
    }

    public class UInt16ConverterForTooltip : IValueConverter
    {
        // converts number to/from display format UInt 16 bit respecting inverse of Hex property (for feeding tooltip)

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.Instance.UIntToStringHexInverse((uint)value, 4);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class UInt16MultiConverter : IMultiValueConverter
    {
        // converts number to/from display format UInt16
        // also takes value of IP4Hex as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.Instance.UIntToStringHex((uint)values[0], 4);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            ulong? u;
            object[] v = new object[3];
            // copy current values of hex and usealiases into result to be sent back - multi value converter must pass back values for all bindings in the multibinding
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            u = GUIUtil.Instance.StringToUInt((string)value);
            if (u == null) v[0] = 0;
            else if (u > 0xffff) v[0] = 0xffff;
            else v[0] = u;

            return v;
        }
    }

    public class UInt16MultiConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.Instance.UIntToStringHexInverse((uint)values[0], 4);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }


    
}
