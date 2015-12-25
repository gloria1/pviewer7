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
    [Serializable]
    public class FilterSet : INotifyPropertyChanged
    // a FilterSet is a list of Filter objects
    // FilterSet.Include returns true if ANY Filter returns true
    // FilterSet.Include returns false if list is empty
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
            bool include = false;   // the default result is to not include the packet, unless one of the filters says to include it

            foreach (Filter f in Filters)
                if (f.Active)
                    if (f.Match(pkt))
                    {
                        if (f.InclusionFilter == InclExcl.Exclude) return false;   // immediately return false if packet matches on an exclusion filter
                        else include = true;     // else set include=true but continue through filter list in case another filter causes exclusion
                    }

            return include;
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
        private InclExcl _inclfilter;
        public InclExcl InclusionFilter { get { return _inclfilter; } set { _inclfilter = value; if (Parent != null) Parent.ChangedSinceApplied = true;
                if (Parent != null) Parent.ChangedSinceSave = true;
            }
        }
        public ObservableCollection<FilterItem> filterlist { get; set; }
        public FilterSet Parent = null;
        public string DisplayInfo
        {
            get
            {
                return String.Format("Filter with {0} items", filterlist.Count()-1);
            }
        }

        // constructors
        public Filter() : this(null) { }
        public Filter(FilterSet parent)  // this is the master, general constructor
        {
            Active = true;
            InclusionFilter = InclExcl.Include;
            filterlist = new ObservableCollection<FilterItem>();
            filterlist.Add(new FilterItemAddItem(this));
            Parent = parent;
        }

        public bool Match(Packet pkt)
        // must match on ALL filter items to return true
        {
            foreach (FilterItem fi in filterlist) if (fi.Match(pkt) == false) return false;
            return true;
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
            return false;   // always return false, i.e. packet does not match this filter
        }
    }


    [Serializable]
    public class FilterItem
    {
        public Filter Parent { get; set; } = null;

        public virtual bool Match(Packet pkt)
        {
            return false;
        }

    }


    [Serializable]
    public class FilterItemIP4 : FilterItem
    {
        private SrcDest _srcdest = SrcDest.Either;
        public SrcDest Srcdest{ get { return _srcdest; } set { _srcdest= value; if (Parent != null) { Parent.Parent.ChangedSinceApplied = true; Parent.Parent.ChangedSinceSave = true; } } }
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
        public FilterItemIP4(Filter parent)
        {
            Parent = parent;
        }
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
    public class FilterItemAddItem : FilterItem
    // special item, of which there will always be exactly one at the end of the filterset
    // purpose is to have a data template that will show an add button at the end of the filterset list in the gui
    {
        public FilterItemAddItem() : this(null) { }
        public FilterItemAddItem(Filter parent)
        {
            Parent = parent;
        }

        public override bool Match(Packet pkt)
        {
            return true;
        }
    }


}