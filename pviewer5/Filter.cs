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
    /* 
        NEXT SET OF CLASSES IS THE UNDERLYING MODEL FOR FILTERS
        IT IS FOLLOWED BY THE VIEWMODEL CLASSES
    */

    [Serializable]
    public class FilterSet
    // a FilterSet is a list of Filter objects
    // FilterSet.Include returns true only if ALL Filters return true (or if list is empty)
    // FilterSet.Include returns true if list is empty
    {
        [field: NonSerializedAttribute]
        private FilterSetVM _viewmodel;
        public FilterSetVM ViewModel { get { return _viewmodel; }  set { _viewmodel = value; } }
        public string Filename { get; set; }
        public bool ChangedSinceSave { get; set; }
        public bool ChangedSinceApplied { get; set; }
        public List<Filter> Filters { get; set; }

        // constructors - from a filename, and an empty constructor
        public FilterSet() : this(null) { }
        public FilterSet(string fn)
        {
            Filename = null;
            ChangedSinceApplied = false;
            ChangedSinceSave = false;
            Filters = new List<Filter>();
            if (fn != null)
            {
                // do stuff to load a file
            }
        }

        public bool Include(Packet pkt)  // returns true if packet should be included based on this filterset
        {
            foreach (Filter f in Filters)
                if (f.Active)
                    if (!f.Match(pkt)) return false;

            return true;  // the default result is to include the packet, unless one of the filters says to not include it
        }

        public void SaveToDisk(string fn)
        // save to file fn - if fn is null, do nothing
        // DOES NOT ASK TO OVERWRITE
        {
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null) return;

            Filename = fn;

            fs = new FileStream(Filename, FileMode.OpenOrCreate);
            formatter.Serialize(fs, Filters);
            fs.Close();
            ChangedSinceSave = false;
        }
        public void SaveAsToDisk()
        {
            SaveFileDialog dlg;

            dlg = new SaveFileDialog();
            dlg.InitialDirectory = "c:\\pviewer\\";
            if (Filename != null) dlg.FileName = Filename;
            dlg.DefaultExt = ".filterset";
            dlg.OverwritePrompt = true;
            if (dlg.ShowDialog() == false) return;
            Filename = dlg.FileName;

            SaveToDisk(Filename);
        }
        public void LoadFromDisk(string fn)
        // if filename is null, open an openfiledialog
        {
            OpenFileDialog dlg;
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null)
            {
                dlg = new OpenFileDialog();
                dlg.InitialDirectory = "c:\\pviewer\\";
                dlg.DefaultExt = ".filterset";
                dlg.Multiselect = false;

                if (dlg.ShowDialog() == true) Filename = dlg.FileName;
                else return;
            }
            else Filename = fn;

            fs = new FileStream(Filename, FileMode.Open);

            try
            {
                Filters = ((List<Filter>)(formatter.Deserialize(fs)));
                ChangedSinceSave = false;
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


    [Serializable]
    public class Filter
    // list of FilterItems
    // Filter.Include returns true only if ALL FilterItem.Match calls return true
    // or if list of filteritems is empty
    {
        private bool _active;
        public bool Active
        {
            get { return _active; }
            set
            {
                _active = value;
                if (Parent != null) Parent.ChangedSinceApplied = true;
                if (Parent != null) Parent.ChangedSinceSave = true;
            }
        }
        public List<FilterItem> filterlist { get; set; }
        public FilterSet Parent = null;

        // constructors
        public Filter() : this(null) { }   // empty constructor, needed for deserialization
        public Filter(FilterSet parent)  // this is the master, general constructor
        {
            Active = true;
            filterlist = new List<FilterItem>();
            Parent = parent;
        }

        public bool Match(Packet pkt)
        // returns true if ANY FilterItems match
        {
            foreach (FilterItem fi in filterlist) if (fi.Match(pkt) == true) return true;
            return false;
        }

    }

    [Serializable]
    public class FilterItem
    // the generic template for specific filter item types
    {
        private FilterType _type = FilterType.Undefined;
        public FilterType Type
        {
            get { return _type; }
            set
            {
                if (_type != value)
                {
                    _type = value;

                    if (Parent == null) return;
                    if (Parent.Parent == null) return;

                    Parent.Parent.ChangedSinceApplied = true;
                    Parent.Parent.ChangedSinceSave = true;
                    int i = Parent.filterlist.IndexOf(this);

                    if (i < 0) return;  // i can be <0 if this setter is called during filteritem construction, before it has been placed in the list

                    FilterItem newitem;
                    switch (value)
                    {
                        case FilterType.IPv4: newitem = new FilterItemIP4(Parent); break;
                        case FilterType.MAC: newitem = new FilterItemMAC(Parent); break;
                        default: newitem = new FilterItem(Parent); break;
                    }
                    Parent.filterlist.Insert(i + 1, newitem);
                    Parent.filterlist.RemoveAt(i);
                }
            }
        }

        public Filter Parent { get; set; } = null;

        public FilterItem() : this(null) { }
        public FilterItem(Filter parent)
        {
            Parent = parent;
        }

        public virtual bool Match(Packet pkt)
        {
            return false;
        }

    }



    [Serializable]
    public enum FilterType: int
    {
        TimeStamp = 1,
        IPv4 = 2,
        MAC = 3,
        Port = 4,
        Protocol = 5,
        GroupType = 6,
        Undefined = 99999
    }

    [Serializable]
    public enum SrcDest : int
    {
        Source = 1,
        Dest = 2,
        Either = 3,
        Undefined = 99999
    }

    [Serializable]
    public enum Relations : int
    {
        Equal = 1,
        NotEqual = 2,
        LessThan = 3,
        LessThanOrEqual = 4,
        GreaterThan = 5,
        GreaterThanOrEqual = 6,
        Undefined = 99999    
    }

    [Serializable]
    public enum InclExcl : int
    {
        Include = 1,
        Exclude = 2,
        Undefined = 99999
    }


    [Serializable]
    public class FilterItemIP4 : FilterItem
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest{ get { return _srcdest; } set { _srcdest = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _value = 0;
        public uint Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _mask = 0xffffffff;
        public uint Mask { get { return _mask; } set { _mask = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }     // bit mask applied to Value and to the packet being tested
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            bool result = false; // default result is to return no match

            uint maskedval;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.SrcIP4 & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.DestIP4 & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            return result;
        }

        public FilterItemIP4() : this(null) { }
        public FilterItemIP4(Filter parent) : base(parent)
        {
            Type = FilterType.IPv4;
            Parent = parent;
        }
    }

    [Serializable]
    public class FilterItemMAC : FilterItem
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest { get { return _srcdest; } set { _srcdest = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private ulong _value = 0;
        public ulong Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private ulong _mask = 0xffffffff;
        public ulong Mask { get { return _mask; } set { _mask = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }     // bit mask applied to Value and to the packet being tested
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            bool result = false; // default result is to return no match

            ulong maskedval;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.SrcMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.DestMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            return result;
        }

        public FilterItemMAC() : this(null) { }
        public FilterItemMAC(Filter parent) : base(parent)
        {
            Type = FilterType.MAC;
            Parent = parent;
        }
    }


    /*
        VIEWMODEL STARTS HERE
    */

    // model <--> viewmodel synchronization
    //    when file is loaded to model, refresh viewmodel -> need a method to do this, 
    //    when changes to model are initiated by viewmodel, vm will fix itself up



    public class FilterSetVM : INotifyPropertyChanged
    {
        public string Filename { get; set; }
        private bool _changedsincesave;
        public bool ChangedSinceSave { get { return _changedsincesave; } set { _changedsincesave = value; NotifyPropertyChanged("ChangedSinceSave"); } }
        private bool _changedsinceapplied;
        public bool ChangedSinceApplied { get { return _changedsinceapplied; } set { _changedsinceapplied = value; NotifyPropertyChanged("ChangedSinceApplied"); } }
        public ObservableCollection<Filter> Filters { get; set; }

        // constructors - from a filename, and an empty constructor
        public FilterSet() : this(null) { }
        public FilterSet(string fn)
        {
            Filename = null;
            PropertyChanged = null;
            ChangedSinceApplied = false;
            ChangedSinceSave = false;
            Filters = new ObservableCollection<Filter>();
            Filters.Add(new FilterAddItem());
            if (fn != null)
            {
                // do stuff to load a file
            }
        }

        public bool Include(Packet pkt)  // returns true if packet should be included based on this filterset
        {
            foreach (Filter f in Filters)
                if (f.Active)
                    if (!f.Match(pkt)) return false;

            return true;  // the default result is to include the packet, unless one of the filters says to not include it
        }

        public void SaveToDisk(string fn)
        // save to file fn - if fn is null, do nothing
        // DOES NOT ASK TO OVERWRITE
        {
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null) return;

            Filename = fn;

            fs = new FileStream(Filename, FileMode.OpenOrCreate);
            formatter.Serialize(fs, Filters);
            fs.Close();
            ChangedSinceSave = false;
        }
        public void SaveAsToDisk()
        {
            SaveFileDialog dlg;

            dlg = new SaveFileDialog();
            dlg.InitialDirectory = "c:\\pviewer\\";
            if (Filename != null) dlg.FileName = Filename;
            dlg.DefaultExt = ".filterset";
            dlg.OverwritePrompt = true;
            if (dlg.ShowDialog() == false) return;
            Filename = dlg.FileName;

            SaveToDisk(Filename);
        }
        public void LoadFromDisk(string fn)
        // if filename is null, open an openfiledialog
        {
            OpenFileDialog dlg;
            FileStream fs;
            IFormatter formatter = new BinaryFormatter();

            if (fn == null)
            {
                dlg = new OpenFileDialog();
                dlg.InitialDirectory = "c:\\pviewer\\";
                dlg.DefaultExt = ".filterset";
                dlg.Multiselect = false;

                if (dlg.ShowDialog() == true) Filename = dlg.FileName;
                else return;
            }
            else Filename = fn;

            fs = new FileStream(Filename, FileMode.Open);

            try
            {
                Filters = ((ObservableCollection<Filter>)(formatter.Deserialize(fs)));
                ChangedSinceSave = false;
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

        // implement INotifyPropertyChanged interface
        [field: NonSerializedAttribute()]
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

    }


    public class FilterVM : INotifyPropertyChanged
    // list of FilterItems
    // Filter.Include returns true only if ALL FilterItem.Match calls return true
    // or if list of filteritems is empty
    {
        private bool _active;
        public bool Active
        {
            get { return _active; }
            set
            {
                _active = value;
                NotifyPropertyChanged();
                if (Parent != null) Parent.ChangedSinceApplied = true;
                if (Parent != null) Parent.ChangedSinceSave = true;
            }
        }
        public ObservableCollection<FilterItem> filterlist { get; set; }
        public FilterSet Parent = null;
        public string DisplayInfo
        {
            get
            {
                return String.Format("Filter with {0} items", filterlist.Count() - 1);
            }
        }

        // constructors
        public Filter() : this(null) { }   // empty constructor, needed for deserialization
        public Filter(FilterSet parent)  // this is the master, general constructor
        {
            Active = true;
            filterlist = new ObservableCollection<FilterItem>();
            filterlist.Add(new FilterItemAddItem(this));
            Parent = parent;
        }

        public bool Match(Packet pkt)
        // returns true if ANY FilterItems match
        {
            foreach (FilterItem fi in filterlist) if (fi.Match(pkt) == true) return true;
            return false;
        }

        //// implement INotifyPropertyChanged interface
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


    }

    public class FilterAddItemVM : FilterVM
    // special item, of which there will always be exactly one at the end of the filterset
    // purpose is to have a data template that will show an add button at the end of the filterset list in the gui
    {
        public FilterAddItem()
        {
            Active = false;   // so it will be ignored in any filter testing
        }

        public new bool Match(Packet pkt)
        {
            // below should be redundant, since Active is set to false in the constructor....
            return true;   // always return true - Filter.Match should return true if list is empty of actual filters (i.e., FilterAddItem is the only item) or if the list is not empty and the testing has reached this item because all previous filters returned true
        }
    }


    public class FilterItemVM
    // the generic template for specific filter item types
    {
        private FilterType _type = FilterType.Undefined;
        public FilterType Type
        {
            get { return _type; }
            set
            {
                if (_type != value)
                {
                    _type = value;

                    if (Parent == null) return;
                    if (Parent.Parent == null) return;

                    Parent.Parent.ChangedSinceApplied = true;
                    Parent.Parent.ChangedSinceSave = true;
                    int i = Parent.filterlist.IndexOf(this);

                    if (i < 0) return;  // i can be <0 if this setter is called during filteritem construction, before it has been placed in the list

                    FilterItem newitem;
                    switch (value)
                    {
                        case FilterType.IPv4: newitem = new FilterItemIP4(Parent); break;
                        case FilterType.MAC: newitem = new FilterItemMAC(Parent); break;
                        default: newitem = new FilterItem(Parent); break;
                    }
                    Parent.filterlist.Insert(i + 1, newitem);
                    Parent.filterlist.RemoveAt(i);
                }
            }
        }

        public Filter Parent { get; set; } = null;

        public FilterItem() : this(null) { }
        public FilterItem(Filter parent)
        {
            Parent = parent;
        }

        public virtual bool Match(Packet pkt)
        {
            return false;
        }

    }

    


    public class FilterItemIP4VM : FilterItemVM
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest { get { return _srcdest; } set { _srcdest = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _value = 0;
        public uint Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _mask = 0xffffffff;
        public uint Mask { get { return _mask; } set { _mask = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }     // bit mask applied to Value and to the packet being tested
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            bool result = false; // default result is to return no match

            uint maskedval;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.SrcIP4 & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.DestIP4 & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            return result;
        }

        public FilterItemIP4() : this(null) { }
        public FilterItemIP4(Filter parent) : base(parent)
        {
            Type = FilterType.IPv4;
            Parent = parent;
        }
    }

    public class FilterItemMACVM : FilterItemVM
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest { get { return _srcdest; } set { _srcdest = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private ulong _value = 0;
        public ulong Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private ulong _mask = 0xffffffff;
        public ulong Mask { get { return _mask; } set { _mask = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }     // bit mask applied to Value and to the packet being tested
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            bool result = false; // default result is to return no match

            ulong maskedval;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.SrcMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskedval = (pkt.DestMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskedval == Value); break;
                    case Relations.NotEqual: result = (maskedval != Value); break;
                    case Relations.LessThan: result = (maskedval < Value); break;
                    case Relations.LessThanOrEqual: result = (maskedval <= Value); break;
                    case Relations.GreaterThan: result = (maskedval > Value); break;
                    case Relations.GreaterThanOrEqual: result = (maskedval >= Value); break;
                    default: break;  // retain previously set value of result
                }
            }
            return result;
        }

        public FilterItemMAC() : this(null) { }
        public FilterItemMAC(Filter parent) : base(parent)
        {
            Type = FilterType.MAC;
            Parent = parent;
        }
    }

    public class FilterItemAddItemVM : FilterItemVM
    // special item, of which there will always be exactly one at the end of the filterset
    // purpose is to have a data template that will show an add button at the end of the filterset list in the gui
    {
        public FilterItemAddItem() : this(null) { }
        public FilterItemAddItem(Filter parent) : base(parent)
        {
            Parent = parent;
        }

        public override bool Match(Packet pkt)
        {
            return false;  // match logic returns true if any FilterItem matches, so this stub item should not indicate a match
        }
    }

}