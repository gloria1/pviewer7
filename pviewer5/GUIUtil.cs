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

        public static string UInt16ToString(uint value, bool inverthex, bool usealiasesthistime)
        // if inverthex==true, return based on !Hex
        // usealiasesthistime parameter copied from IP4 code, not used yet, but someday may add Port number map
        {
            if (inverthex ^ GUIUtil.Instance.Hex) return String.Format("{0:x4}", value);
            else return String.Format("{0}", value);
        }

        public static string UInt16ToStringAlts(uint value)
        // return strings of forms other than what would be returned by ToString
        //      numerical form indicated by !Hex
       {
            if (!GUIUtil.Instance.Hex) return String.Format("{0:x4}", value);
            else return String.Format("{0}", value);
        }

        public static bool UInt16TryParse(string s, ref uint value)
        // tries to parse string into value, respecting global Hex flag
        // fails if value is > 0xffff
        // if any errors, returns false and does not assign value
        {
            NumberStyles style = (GUIUtil.Instance.Hex ? NumberStyles.HexNumber : NumberStyles.Integer);
            uint result;

            // try to parse, if it fails fall through to return false
            try
            {
                result = uint.Parse(s, style);
                if (result > 0xffff) return false;
                value = result;
                return true;
            }
            catch (FormatException ex)
            {
            }

            return false;

        }


        public static string DateTimeToString(DateTime value)
        {
            return value.ToString("yyyy-MM-dd HH:mm:ss.fffffff");
        }

        public static bool DateTimeTryParse(string s, ref DateTime value)
        // tries to parse string into value
        // if any errors, returns false and does not assign value
        {
            DateTime result;
            CultureInfo culture;
            DateTimeStyles styles;
            culture = CultureInfo.CreateSpecificCulture("en-US");
            styles = DateTimeStyles.AssumeLocal;

            // Parse a date and time with no styles.

            // try to parse, if it fails fall through to return false
            try
            {
                result = new DateTime(0);
                if (DateTime.TryParse(s, culture, styles, out result))
                {
                    value = new DateTime(1);
                    return true;
                }
            }
            catch (FormatException ex)
            {
            }

            return false;

        }



    }


    public class ValidateUInt16 : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            uint i = 0;

            if (GUIUtil.UInt16TryParse((string)value, ref i)) return new ValidationResult(true, "Valid IP4 Address");
            else return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class UInt16Converter : IValueConverter
    {
        // converts number to/from display format IP4 address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.UInt16ToString((uint)value, false, true);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            uint i = 0;
            if (GUIUtil.UInt16TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class UInt16ConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format IP4 address
        // does not convert aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.UInt16ToString((uint)value, false, false);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            uint i = 0;
            if (GUIUtil.UInt16TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class UInt16ConverterForTooltip : IValueConverter
    {
        // converts number to display format IP4 address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.UInt16ToStringAlts((uint)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class UInt16MVConverter : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.UInt16ToString((uint)values[0], false, true);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            uint i = 0;
            object[] v = new object[3];
            v[0] = (uint)0;
            // set v[1] and v[2] - not sure if they need to be set to their actual values, but not setting them at all leaves
            // them null, and then validation fails even if input if valid
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            if (GUIUtil.UInt16TryParse((string)value, ref i))
            {
                v[0] = i;
                return v;
            }
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return v;
        }
    }

    public class UInt16MVConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.UInt16ToStringAlts((uint)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }


    public class ValidateDateTime : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            DateTime d = new DateTime(0);

            if (GUIUtil.DateTimeTryParse((string)value, ref d)) return new ValidationResult(true, "Valid IP4 Address");
            else return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class DateTimeConverter : IValueConverter
    {
        // converts number to/from display format IP4 address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.DateTimeToString((DateTime)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            DateTime d = new DateTime(0);
            if (GUIUtil.DateTimeTryParse((string)value, ref d)) return d;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return d;
        }
    }

    public class DateTimeConverterForTooltip : IValueConverter
    {
        // converts number to display format IP4 address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.DateTimeToString((DateTime)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class DateTimeMVConverter : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.DateTimeToString((DateTime)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            DateTime d = new DateTime(0);
            object[] v = new object[3];
            v[0] = d;
            // set v[1] and v[2] - not sure if they need to be set to their actual values, but not setting them at all leaves
            // them null, and then validation fails even if input if valid
            v[1] = GUIUtil.Instance.Hex;
            v[2] = GUIUtil.Instance.UseAliases;

            if (GUIUtil.DateTimeTryParse((string)value, ref d))
            {
                v[0] = d;
                return v;
            }
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return v;
        }
    }

    public class DateTimeMVConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return GUIUtil.DateTimeToString((DateTime)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }





}
