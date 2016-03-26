﻿using System;
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



    public class IP4Util
    // class containing:
    //      utility functions related to IP4 addresses (value converters, etc.)
    // this is implemented as a dynamic class as a Singleton, i.e., there can only ever be one instance
    // this is because static classes cannot implement interfaces (or at least INotifyPropertyChanged)
    {
        private static readonly IP4Util instance = new IP4Util();
        public static IP4Util Instance { get { return instance; } }

      // private constructor below was set up per the "singleton" pattern, so that no further instances of this class could be created
        // however, for some reason this caused the data binding to IP4Hex to stop working, so i have commented this out
        /* private IP4Util()
        // constructor is private, so no one else can call it - the singleton instance was created in the initialization of Instance above
        {
            return;
        }*/

  
        [Serializable]
        public class inmdict : Dictionary<uint, string>
        // data model for a mapping of IP4 addresses to aliases
        {
            // need the following constructor (from ISerializable, which is inherited by Dictionary)
            protected inmdict(SerializationInfo info, StreamingContext ctx) : base(info, ctx) { }
            // need to explicitly declare an empty constructor, because without this, new tries to use the above constructor
            public inmdict() { }

            public void maptotable(inmtable table)	// transfers IP4namemap dictionary to a table to support a datagrid
            {
                foreach (uint k in this.Keys) table.Add(new inmtableitem(k, this[k], table));
            }
        }

        public inmdict map = new inmdict()
        {
                {0x00000000, "ALL ZEROES"},
        };


        BOOKMARK
            RE-THINK CHANGE PROPAGATION BETWEEN DICT AND TABLE AND GUI
                DICT CHANGE DUE TO LOAD/APPEND -> REFRESH TABLE -> REFRESH GUI TABLE -> REFRESH REST OF GUI
                TABLEITEM CHANGE DUE TO USER EDITING -> REFRESH REST OF GUI -> UPDATE DICT
            REVISE IMPLEMENATION OF FILE LOAD/SAVE/APPEND


        public ObservableCollection<inmtableitem> inmtable = new ObservableCollection<inmtableitem>();
        // view model for mapping of IP4 values to aliases



        public class inmtableitem
        {
            public uint IP4 { get; set; }
            public string alias { get; set; }
            public inmtable parent;

            public inmtableitem(uint u, string s, inmtable p)
            {
                IP4 = u;
                alias = s;
                parent = p;
            }
        }


        public static string ToString(uint value, bool inverthex, bool usealiasesthistime)
        // if inverthex==true, return based on !Hex
        // if usealiasesthistime == true, then if global UseAliases is true, return the alias
        {

            if (usealiasesthistime && GUIUtil.Instance.UseAliases)
                if (IP4Util.Instance.map.ContainsKey(value))
                    return IP4Util.Instance.map[value];

            uint[] b = new uint[4];
            string s;

            b[0] = ((value & 0xff000000) / 0x1000000);
            b[1] = ((value & 0xff0000) / 0x10000);
            b[2] = ((value & 0xff00) / 0x100);
            b[3] = ((value & 0xff) / 0x1);

            if (inverthex ^ GUIUtil.Instance.Hex) s = String.Format("{0:x2}.{1:x2}.{2:x2}.{3:x2}", b[0], b[1], b[2], b[3]);
            else s = String.Format("{0}.{1}.{2}.{3}", b[0], b[1], b[2], b[3]);

            return s;
        }

        public static string ToStringAlts(uint value)
        // return strings of forms other than what would be returned by ToString
        //      numerical form indicated by !Hex
        //      if UseAliases, then numerical form based on Hex
        //      if !UseAliases, then alias if there is one
        {
            string s = null;

            s = IP4Util.ToString(value, true, false);
            s += "\n";
            if (IP4Util.Instance.map.ContainsKey(value))
            {
                // if UseAliases, then, if this IP has an alias, we want to append the non-inverthex numerical form
                if (GUIUtil.Instance.UseAliases) s += IP4Util.ToString(value, false, false);
                // else return the alias
                else s += IP4Util.Instance.map[value];
            }

            return s;
        }

        public static bool TryParse(string s, ref uint value)
        // tries to parse string into value
        // first tries to parse a simple number, respecting global Hex flag
        // if that fails, tries to parse as a numerical dot format address, respecting global Hex flag
        // if that fails, checks for match of an alias
        // if no match or any errors, returns false and does not assign value
        {
            // first try to parse as a raw IP4 address
            string[] IP4bits = new string[4];
            NumberStyles style = (GUIUtil.Instance.Hex ? NumberStyles.HexNumber : NumberStyles.Integer);
            string regexIP4 = (GUIUtil.Instance.Hex ? "^(0*[a-fA-F0-9]{0,2}.){0,3}0*[a-fA-F0-9]{0,2}$" : "^([0-9]{0,3}.){0,3}[0-9]{0,3}$");

            try
            {
                value = uint.Parse(s, style);
                return true;
            }
            // if could not parse as simple number
            catch (FormatException ex)
            {
                // try parsing as dot notation
                if (Regex.IsMatch(s, regexIP4))
                {
                    IP4bits = Regex.Split(s, "\\.");
                    // resize array to 4 - we want to tolerate missing dots, i.e., user entering less than 4 segments,
                    // split will produce array with number of elements equal to nmber of dots + 1
                    Array.Resize<string>(ref IP4bits, 4);

                    for (int i = 0; i < 4; i++) { IP4bits[i] = "0" + IP4bits[i]; }

                    try
                    {
                        value = uint.Parse(IP4bits[0], style) * 0x0000000001000000 +
                            uint.Parse(IP4bits[1], style) * 0x0000000000010000 +
                            uint.Parse(IP4bits[2], style) * 0x0000000000000100 +
                            uint.Parse(IP4bits[3], style) * 0x0000000000000001;
                        return true;
                    }
                    catch { }
                }
                // if we have gotten this far, s was not parsed as a simple number or dot notation number, so check if it is a valid alias
                foreach (uint u in IP4Util.Instance.map.Keys)
                    if (s == IP4Util.Instance.map[u])
                    {
                        value = u;
                        return true;
                    }

                // if we get to here, s could not be parsed in any valid way, so return false;
                return false;
            }

        }



    }



    public class ValidateIP4 : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            uint i = 0;

            if (IP4Util.TryParse((string)value, ref i)) return new ValidationResult(true, "Valid IP4 Address");
            else return new ValidationResult(false, "Not a valid IP4 address");
        }
    }

    public class IP4Converter : IValueConverter
    {
        // converts number to/from display format IP4 address

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.ToString((uint)value, false, true);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            uint i = 0;
            if (IP4Util.TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class IP4ConverterNumberOnly : IValueConverter
    {
        // converts number to/from display format IP4 address
        // does not convert aliases

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.ToString((uint)value, false, false);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            uint i = 0;
            if (IP4Util.TryParse((string)value, ref i)) return i;
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return 0;
        }
    }

    public class IP4ConverterForTooltip : IValueConverter
    {
        // converts number to display format IP4 address strings
        // this returns a string containing all forms other than that returned by normal converter
        // this is to feed tooltips

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.ToStringAlts((uint)value);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }
    }

    public class IP4MVConverter : IMultiValueConverter
    {
        // converts number to/from display format IP4 address, including translating aliases
        // takes two additional arguments, because this will be used as part of a MultiBinding that also binds to Hex and UseAliases

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.ToString((uint)values[0], false, true);
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

            if (IP4Util.TryParse((string)value, ref i))
            {
                v[0] = i;
                return v;
            }
            // the tryparse should never fail because Validation should have prevented any errors, but just in case, return a zero value
            else return v;
        }
    }

    public class IP4MVConverterForTooltip : IMultiValueConverter
    {

        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            return IP4Util.ToStringAlts((uint)values[0]);
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException("Cannot convert back");
        }

    }

}
