package xml;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.ArrayList;
import java.util.List;

@XmlRootElement(name = "Keys")
public class KeysXML {
    @XmlElement(name = "erziehungsberechtigter")
    public List<String> erziehungsberechtigte = new ArrayList<>();
    @XmlElement(name = "sonstiger")
    public List<String> sonstige = new ArrayList<>();


}
