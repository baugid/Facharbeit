package xml;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "Metadaten")
public class MetadatenXML {
    public KlassenlehrerXML klassenlehrer;
    public ListeFachlehrerXML alleFachlehrer;
    public SchulleiterungXML schulleiterung;
}
