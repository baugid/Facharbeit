package xml;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "Noten")
public class NotenXML {
    @XmlElement(name = "note")
    public List<NoteXML> noten = new ArrayList<>();

}
