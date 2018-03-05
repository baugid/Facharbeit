package xml;

import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "alleFachlehrer")
public class ListeFachlehrerXML {
    public List<FachlehrerXML> fachlehrer = new ArrayList<>();
}
