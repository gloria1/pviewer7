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
        // fixed width if width > 0
        {
            string s;

            if (Hex) s = String.Format("{0:x}", value);
            else s = String.Format("{0}", value);

            if (width > 0)
            {
                if (width > s.Length) s=s.PadLeft(width, '0');
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

            // try to parse as a raw IP4 address
            v = GUIUtil.Instance.StringToUInt(value.ToString());
            if (v == null) return new ValidationResult(false, "Not a valid UInt");
            else if (v > 0xffff) return new ValidationResult(false, "Value Out of Bounds for UInt16");
            else return new ValidationResult(true, "Valid UInt16");
        }
    }

 

    public class Uint16Converter : IValueConverter
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


    /*

    public class IP4ConverterNumberOrAliasInverse : IValueConverter
    // same as IP4ConverterNumberOrAlias except reflects the inverse of the UseAliases property - to feed tooltips
    {
        // converts number to/from display format IP4 address, including translating aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (!GUIUtil.Instance.UseAliases && IP4Util.Instance.map.ContainsKey((uint)value))
                return IP4Util.Instance.map[(uint)value];
            else return IP4Util.Instance.IP4ToString((uint)value);
        }

        public object ConvertBack(object value, Type targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }


    public class IP4MultiConverterNumberOrAlias : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // also takes value of IP4Hex as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (GUIUtil.Instance.UseAliases && IP4Util.Instance.map.ContainsKey((uint)values[0]))
                return IP4Util.Instance.map[(uint)values[0]];
            else return IP4Util.Instance.IP4ToString((uint)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            uint? u;
            object[] v = new object[3];
            // copy current values of hex and usealiases into result to be sent back - multi value converter must pass back values for all bindings in the multibinding
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            // first try to parse as a raw IP4 address
            u = IP4Util.Instance.StringToIP4((string)value);
            if (u != null)
            {
                v[0] = u;
                return v;
            }

            // if that failed, see if string exists in IP4namemap
            foreach (uint uu in IP4Util.Instance.map.Keys)
                if ((string)value == IP4Util.Instance.map[uu])
                {
                    v[0] = uu;
                    return v;
                }

            // we should never get to this point, since validation step will not pass unless value is either valid raw IP4 or existing entry in IP4namemap
            // however, just in case put up a messagebox and return 0
            MessageBox.Show("ConvertBack could not process as either raw IP4 address or entry in IP4namemap.  Why did this pass validation????");
            v[0] = 0; return v;
        }
    }

    public class IP4MultiConverterNumberOrAliasInverse : IMultiValueConverter
    // same as above except respects the inverse of UseAliases
    {
        // converts number to/from display format IP4 address, including translating aliases
        // also takes value of IP4Hex as an argument

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (!GUIUtil.Instance.UseAliases && IP4Util.Instance.map.ContainsKey((uint)values[0]))
                return IP4Util.Instance.map[(uint)values[0]];
            else return IP4Util.Instance.IP4ToString((uint)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }

*/
}
