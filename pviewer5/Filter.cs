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


    public class FilterSet : INotifyPropertyChanged
    // a FilterSet is a list of Filter objects
    // FilterSet.Include returns true only if ALL Filters return true (or if list is empty)
    // FilterSet.Include returns true if list is empty
    {
        public string Filename { get; set; }
        private bool _changedsincesave;
        public bool ChangedSinceSave { get { return _changedsincesave; } set { _changedsincesave = value; NotifyPropertyChanged(); } }
        private bool _changedsinceapplied;
        public bool ChangedSinceApplied { get { return _changedsinceapplied; } set { _changedsinceapplied = value; NotifyPropertyChanged(); } }
        public ObservableCollection<Filter> Filters { get; set; }

        // constructors - from a filename, and an empty constructor
        public FilterSet() : this(null) { }
        public FilterSet(string fn)
        {
            Filename = null;
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
            int numfilters = Filters.Count() - 1;  // do not count the FilterAddItem
            formatter.Serialize(fs, numfilters);
            for (int i = 0; i < numfilters;  i++) Filters[i].SerializeMyself(fs, formatter);
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

            Filters.Clear();

            try
            {
                fs = new FileStream(Filename, FileMode.Open);
                int numfilters = (int)formatter.Deserialize(fs);
                for (int i = 0; i < numfilters; i++) Filters.Add(new Filter(this, fs, formatter));
                ChangedSinceApplied = ChangedSinceSave = false;
                fs.Close();
            }
            catch
            {
                MessageBox.Show("File not read");
            }

            Filters.Add(new FilterAddItem());

        }

        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }

    }


    [Serializable]
    public class Filter : INotifyPropertyChanged
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
        
        [field:NonSerialized]
        public FilterSet Parent = null;

        public string DisplayInfo
        {
            get
            {
                return String.Format("Filter with {0} items", filterlist.Count()-1);
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
        public Filter(FilterSet parent, FileStream fs, IFormatter formatter)    // constructor for when de-serializing
        {
            Parent = parent;
            Active = (bool)formatter.Deserialize(fs);
            filterlist = (ObservableCollection<FilterItem>)formatter.Deserialize(fs);
            foreach (FilterItem i in filterlist) i.Parent = this;   // parent attribute not serialized, so set it manually
        }

        public void SerializeMyself(FileStream fs, IFormatter formatter)
        {
            formatter.Serialize(fs, Active);
            formatter.Serialize(fs, filterlist);
        }

        public bool Match(Packet pkt)
        // returns true if ANY FilterItems match
        {
            foreach (FilterItem fi in filterlist) if (fi.Match(pkt) == true) return true;
            return false;
        }


        // implement INotifyPropertyChanged interface
        [field:NonSerializedAttribute()]
        public event PropertyChangedEventHandler PropertyChanged;
        private void NotifyPropertyChanged(String propertyName = "")
        {
            if (PropertyChanged != null)
            {
                PropertyChanged(this, new PropertyChangedEventArgs(propertyName));
            }
        }


    }

    [Serializable]
    public class FilterAddItem : Filter
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
                        case FilterType.DateTime: newitem = new FilterItemDateTime(Parent); break;
                        case FilterType.IPv4: newitem = new FilterItemIP4(Parent); break;
                        case FilterType.MAC: newitem = new FilterItemMAC(Parent); break;
                        case FilterType.Port: newitem = new FilterItemPort(Parent); break;
                        default: newitem = new FilterItem(Parent); break;
                    }
                    Parent.filterlist.Insert(i + 1, newitem);
                    Parent.filterlist.RemoveAt(i);
                }
            }
        }

        [field:NonSerialized]
        private Filter _parent = null;
        public Filter Parent { get { return _parent; }  set { _parent = value; } }

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
        DateTime = 1,
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

            uint maskedtarget, maskeddata;
            maskedtarget = Value & Mask;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskeddata = pkt.SrcIP4 & Mask;
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskeddata = (pkt.DestIP4 & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
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

            ulong maskedtarget, maskeddata;
            maskedtarget = Value & Mask;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskeddata = (pkt.SrcMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskeddata = (pkt.DestMAC & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
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

    [Serializable]
    public class FilterItemPort : FilterItem
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest { get { return _srcdest; } set { _srcdest = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _value = 0;
        public uint Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private uint _mask = 0xffff;
        public uint Mask { get { return _mask; } set { _mask = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }     // bit mask applied to Value and to the packet being tested
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            bool result = false; // default result is to return no match

            uint maskedtarget, maskeddata;
            maskedtarget = Value & Mask;

            if ((Srcdest == SrcDest.Source) || (Srcdest == SrcDest.Either))
            {
                maskeddata = pkt.SrcPort & Mask;
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
                    default: break;  // retain previously set value of result
                }
            }
            if (result == true) return true;

            if ((Srcdest == SrcDest.Dest) || (Srcdest == SrcDest.Either))
            {
                maskeddata = (pkt.DestPort & Mask);
                switch (Relation)
                {
                    case Relations.Equal: result = (maskeddata == maskedtarget); break;
                    case Relations.NotEqual: result = (maskeddata != maskedtarget); break;
                    case Relations.LessThan: result = (maskeddata < maskedtarget); break;
                    case Relations.LessThanOrEqual: result = (maskeddata <= maskedtarget); break;
                    case Relations.GreaterThan: result = (maskeddata > maskedtarget); break;
                    case Relations.GreaterThanOrEqual: result = (maskeddata >= maskedtarget); break;
                    default: break;  // retain previously set value of result
                }
            }
            return result;
        }

        public FilterItemPort() : this(null) { }
        public FilterItemPort(Filter parent) : base(parent)
        {
            Type = FilterType.Port;
            Parent = parent;
        }
    }

    [Serializable]
    public class FilterItemDateTime : FilterItem
    {
        private DateTime _value = new DateTime(0);
        public DateTime Value { get { return _value; } set { _value = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
        private Relations _relation = Relations.Equal;
        public Relations Relation { get { return _relation; } set { _relation = value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }

        public override bool Match(Packet pkt)
        {
            switch (Relation)
            {
                case Relations.Equal: return (pkt.Time == Value);
                case Relations.NotEqual: return (pkt.Time != Value);
                case Relations.LessThan: return (pkt.Time < Value);
                case Relations.LessThanOrEqual: return (pkt.Time <= Value);
                case Relations.GreaterThan: return (pkt.Time > Value); 
                case Relations.GreaterThanOrEqual: return (pkt.Time >= Value);
                default: return false; 
            }
        }

        public FilterItemDateTime() : this(null) { }
        public FilterItemDateTime(Filter parent) : base(parent)
        {
            Type = FilterType.DateTime;
            Parent = parent;
        }
    }

    [Serializable]
    public class FilterItemAddItem : FilterItem
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