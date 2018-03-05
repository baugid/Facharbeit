package xml;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Note")
public class NoteXML {
    public short zensur;
    public short fach;
    public String fachlehrer;

}
