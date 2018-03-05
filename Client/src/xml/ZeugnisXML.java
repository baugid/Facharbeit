package xml;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;


@XmlRootElement(name = "Zeugnis")
public class ZeugnisXML {
    @XmlAttribute
    public short vers;
    public short jahr;
    public String Schueler;
    public KeysXML besitzer;
    public SchuleXML schule;
    public NotenXML noten;
    public String bemerkungen;

}
